//! Complete legacy kind/level declarations; no record evaluation.
use super::value_rules::{ValueRules, checked_value_rules};
use super::{
    CommandInputs, PolicyError, checked_base_inputs, checked_command_inputs, invalid, names,
};
use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Serialize)]
pub struct KindRule {
    #[serde(flatten)]
    pub inputs: CommandInputs,
    pub runner_prefix: Option<String>,
    pub trust_levels: Option<Vec<String>>,
    #[serde(serialize_with = "super::serialize_pairs")]
    pub by_level: Vec<(String, LevelRule)>,
    #[serde(flatten)]
    pub values: ValueRules,
    #[serde(serialize_with = "super::serialize_pairs")]
    pub base_inputs: Vec<(String, String)>,
}
#[derive(Debug, Serialize)]
pub struct LevelRule {
    #[serde(flatten)]
    pub inputs: CommandInputs,
    pub events: Vec<String>,
    pub lane: LaneBinding,
}
#[derive(Debug)]
pub enum LaneBinding {
    None,
    Base,
    Tree,
}
impl Serialize for LaneBinding {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::None => serializer.serialize_bool(false),
            Self::Base => serializer.serialize_bool(true),
            Self::Tree => serializer.serialize_str("tree"),
        }
    }
}

pub fn checked_kinds(
    kinds: Map<String, Value>,
    levels: &[String],
    repository: &str,
    check: &str,
) -> Result<Vec<(String, KindRule)>, PolicyError> {
    kinds
        .into_iter()
        .map(|(kind, raw)| {
            let error = || {
                invalid(format!(
                    "skip policy for {check}/{kind}: invalid kind or level rule"
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
            }) {
                return Err(error());
            }
            let where_ = format!("{check}/{kind}");
            let inputs = checked_command_inputs(&mut rule, &where_)?;
            let values = checked_value_rules(&mut rule, &where_)?;
            let base_inputs = checked_base_inputs(&mut rule, &where_)?;
            let trust_levels = match rule.remove("trust_levels") {
                None | Some(Value::Null) => None,
                Some(value) => Some(names(value).ok_or_else(error)?),
            };
            let runner_prefix = match rule.remove("runner_prefix") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if !value.is_empty() => {
                    Some(fill(value, repository, check))
                }
                _ => return Err(error()),
            };
            let overrides = match rule.remove("by_level").unwrap_or(Value::Null) {
                Value::Object(map) => map,
                Value::Null | Value::Bool(false) => Map::new(),
                Value::String(s) if s.is_empty() => Map::new(),
                Value::Array(a) if a.is_empty() => Map::new(),
                Value::Number(n) if n.as_f64() == Some(0.0) => Map::new(),
                _ => return Err(error()),
            };
            let mut by_level = Vec::with_capacity(overrides.len());
            for (level, raw) in overrides {
                if level.is_empty() || !trust_levels.as_deref().unwrap_or(levels).contains(&level) {
                    return Err(error());
                }
                let Value::Object(mut fields) = raw else {
                    return Err(error());
                };
                if fields.keys().any(|key| {
                    ![
                        "command",
                        "required_inputs",
                        "bind_inputs",
                        "events",
                        "lane",
                    ]
                    .contains(&key.as_str())
                }) {
                    return Err(error());
                }
                let events = fields
                    .remove("events")
                    .and_then(names)
                    .filter(|events| {
                        events
                            .iter()
                            .all(|event| matches!(event.as_str(), "pull_request" | "merge_group"))
                            && (events.len() == 1 || (events.len() == 2 && events[0] != events[1]))
                    })
                    .ok_or_else(error)?;
                let inputs = checked_command_inputs(&mut fields, &format!("{where_}/{level}"))?;
                let lane = match fields.remove("lane") {
                    None | Some(Value::Bool(false)) => LaneBinding::None,
                    Some(Value::Bool(true)) => LaneBinding::Base,
                    Some(Value::String(s)) if s == "tree" => LaneBinding::Tree,
                    _ => return Err(error()),
                };
                by_level.push((
                    level,
                    LevelRule {
                        inputs: normalized(inputs, repository, check),
                        events,
                        lane,
                    },
                ));
            }
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
fn fill(mut value: String, repository: &str, check: &str) -> String {
    for (placeholder, replacement) in [("{repository}", repository), ("{check}", check)] {
        if value.contains(placeholder) {
            value = value.replace(placeholder, replacement);
        }
    }
    value
}
fn normalized(mut inputs: CommandInputs, repository: &str, check: &str) -> CommandInputs {
    inputs.command = inputs
        .command
        .into_iter()
        .map(|v| fill(v, repository, check))
        .collect();
    inputs.required_inputs.sort_unstable();
    inputs.required_inputs.dedup();
    for (key, _) in &inputs.bind_inputs {
        if let Err(index) = inputs.required_inputs.binary_search(key) {
            inputs.required_inputs.insert(index, key.clone());
        }
    }
    inputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
        results.append(oracle['policy_rules'](json.dumps(policy), 'check', 'owner/{check}')['kinds'])
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
            let actual = checked_kinds(
                kinds.as_object().unwrap().clone(),
                &["agent".into()],
                "owner/{check}",
                "check",
            )
            .map(|rules| {
                Value::Object(
                    rules
                        .into_iter()
                        .map(|(kind, rule)| (kind, serde_json::to_value(rule).unwrap()))
                        .collect(),
                )
            })
            .unwrap_or_else(|error| json!({"reason":error.reason}));
            assert_eq!(actual, expected, "{kinds}");
        }
    }
}

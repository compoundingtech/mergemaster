//! Legacy signer-level override declarations; no evidence evaluation.
use super::check_names::CheckName;
use super::normalized_text::NormalizedText;
use super::{
    CommandInputs, PolicyError, checked_command_inputs, exception, invalid, names, rule_error,
};
use crate::evidence::legacy_verify::{failure_json::TextRef, python_repr::Repr};
use serde::Serialize;
use serde_json::{Map, Value};

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
pub fn checked_levels<'a>(
    overrides: Map<String, Value>,
    accepted_levels: &[NormalizedText],
    repository: &str,
    check: impl Into<CheckName<'a>>,
    kind: &str,
) -> Result<Vec<(NormalizedText, LevelRule)>, PolicyError> {
    let check = check.into();
    let kind_context = [check.text(), TextRef::Str("/"), TextRef::Str(kind)];
    let refusal = |level: &str, message: &str| {
        invalid(NormalizedText::concat(
            [
                TextRef::Str("skip policy for "),
                check.text(),
                TextRef::Str("/"),
                TextRef::Str(kind),
            ]
            .into_iter()
            .chain([
                TextRef::Str(": by_level "),
                TextRef::Str(&format!("{}{message}", Repr(TextRef::Str(level)))),
            ]),
        ))
    };
    let mut by_level = Vec::with_capacity(overrides.len());
    for (level, raw) in overrides {
        let Value::Object(mut fields) = raw else {
            return Err(refusal(&level, " is not valid"));
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
        }) || !fields.contains_key("command")
            || !fields.contains_key("events")
        {
            return Err(refusal(&level, " is not valid"));
        }
        if level.is_empty() {
            return Err(refusal(&level, " is not valid"));
        }
        if !accepted_levels.iter().any(|a| a.borrowed().equals(&level)) {
            return Err(refusal(
                &level,
                " is not among the trust levels this kind accepts",
            ));
        }
        let raw_events = fields.remove("events").unwrap_or(Value::Null);
        // Python builds set(events) before checking event membership.
        if let Some(members) = raw_events.as_array().filter(|m| !m.is_empty()) {
            for member in members {
                let kind = match member {
                    Value::Array(_) => "list",
                    Value::Object(_) => "dict",
                    _ => continue,
                };
                return Err(exception(
                    "TypeError",
                    format!("cannot use '{kind}' as a set element (unhashable type: '{kind}')"),
                ));
            }
        }
        let events = names(raw_events)
            .filter(|events| {
                events
                    .iter()
                    .all(|event| matches!(event.as_str(), "pull_request" | "merge_group"))
                    && (events.len() == 1 || (events.len() == 2 && events[0] != events[1]))
            })
            .ok_or_else(|| {
                rule_error(
                    &kind_context,
                    "events must be a nonempty list of pull_request, merge_group",
                )
            })?;
        let inputs = checked_command_inputs(
            &mut fields,
            &[
                check.text(),
                TextRef::Str("/"),
                TextRef::Str(kind),
                TextRef::Str("/"),
                TextRef::Str(&level),
            ],
        )?;
        let lane = match fields.remove("lane") {
            None | Some(Value::Bool(false)) => LaneBinding::None,
            Some(Value::Bool(true)) => LaneBinding::Base,
            Some(Value::String(s)) if s == "tree" => LaneBinding::Tree,
            _ => return Err(refusal(&level, " lane must be true, false or \"tree\"")),
        };
        by_level.push((
            NormalizedText::Scalar(level),
            LevelRule {
                inputs: normalized(inputs, repository, check),
                events,
                lane,
            },
        ));
    }
    Ok(by_level)
}
pub(super) fn fill(
    value: NormalizedText,
    repository: &str,
    check: CheckName<'_>,
) -> NormalizedText {
    value
        .replace("{repository}", TextRef::Str(repository))
        .replace("{check}", check.text())
}
pub(super) fn normalized(
    mut inputs: CommandInputs,
    repository: &str,
    check: CheckName<'_>,
) -> CommandInputs {
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

pub(super) fn serialize_level_pairs<S: serde::Serializer>(
    pairs: &[(NormalizedText, LevelRule)],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(pairs.iter().map(|(key, value)| (key, value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn level_overrides_match_the_pinned_oracle() {
        let mut cases: Vec<Value> = serde_json::from_str(r#"[
          {}, {"agent":null}, {"":{}}, {"host":{"command":["true"],"events":["pull_request"]}},
          {"agent":{"command":["true"]}}, {"agent":{"events":["pull_request"]}},
          {"agent":{"command":["true"],"events":[]}},
          {"agent":{"command":["true"],"events":["pull_request","pull_request"]}},
          {"agent":{"command":["true"],"events":["push"]}},
          {"agent":{"command":["true"],"events":[[]]}},
          {"agent":{"command":["true"],"events":["pull_request"],"unknown":true}},
          {"agent":{"command":["true"],"events":["pull_request"]}},
          {"agent":{"command":["{repository}","{check}"],"events":["merge_group","pull_request"],
            "required_inputs":["z","a","z"],"bind_inputs":{"b":"{check}","a":"literal"},"lane":"tree"}}
        ]"#).unwrap();
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
            cases.push(json!({"agent":{"command":["true"],"events":["pull_request"],"lane":lane}}));
        }
        for field in ["command", "required_inputs", "bind_inputs", "events"] {
            for value in [
                json!(null),
                json!(false),
                json!([]),
                json!({}),
                json!([""]),
                json!([1]),
            ] {
                let mut fields = json!({"command":["true"],"events":["pull_request"]});
                fields[field] = value;
                cases.push(json!({"agent":fields}));
            }
        }
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for overrides in json.loads(sys.argv[2]):
    try:
        entry = dict(trust_levels=['agent'], kinds=dict(wrapper=dict(command=['true'], by_level=overrides)))
        policy = dict(version=1, checks=dict(check=entry))
        results.append(oracle['policy_rules'](json.dumps(policy), 'check', 'owner/{check}')['kinds']['wrapper']['by_level'])
    except (oracle['Failure'], TypeError):
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
        for (overrides, expected) in cases.into_iter().zip(expected) {
            let actual = checked_levels(
                overrides.as_object().unwrap().clone(),
                &["agent".into()],
                "owner/{check}",
                "check",
                "wrapper",
            )
            .map(|rules| {
                Value::Object(
                    rules
                        .into_iter()
                        .map(|(level, rule)| {
                            (
                                level.borrowed().to_string(),
                                serde_json::to_value(rule).unwrap(),
                            )
                        })
                        .collect(),
                )
            })
            .unwrap_or_else(|error| json!({"reason":error.reason}));
            assert_eq!(actual, expected, "{overrides}");
        }
    }
}
#[cfg(test)]
#[path = "level_diagnostics_tests.rs"]
mod diagnostics_tests;

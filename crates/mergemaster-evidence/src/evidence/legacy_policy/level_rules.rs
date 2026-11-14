//! Legacy signer-level override declarations; no evidence evaluation.
use super::check_names::CheckName;
use super::normalized_text::NormalizedText;
use super::value_source::{self, Source};
use super::{CommandInputs, PolicyError, checked_command_inputs, exception, invalid, rule_error};
use crate::evidence::legacy_verify::statement_document::Node;
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
    // Temporary bridge, removed by the step-5 PolicyDocument ingress cutover.
    let document = value_source::bridge(&overrides)?;
    from_source(
        Source::root(&document),
        accepted_levels,
        repository,
        check.into(),
        kind,
    )
}
pub(super) fn from_source(
    overrides: Source<'_>,
    accepted_levels: &[NormalizedText],
    repository: &str,
    check: CheckName<'_>,
    kind: &str,
) -> Result<Vec<(NormalizedText, LevelRule)>, PolicyError> {
    let kind_context = [check.text(), TextRef::Str("/"), TextRef::Str(kind)];
    let refusal = |level: &[u32], message: &str| {
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
                TextRef::Str(&format!("{}{message}", Repr(TextRef::Points(level)))),
            ]),
        ))
    };
    let mut by_level = Vec::new();
    for (level, fields) in overrides.entries().into_iter().flatten() {
        if fields.object().is_none_or(|entries| {
            entries.keys().any(|key| {
                ![
                    "command",
                    "required_inputs",
                    "bind_inputs",
                    "events",
                    "lane",
                ]
                .iter()
                .any(|name| value_source::key_is(key, name))
            })
        }) || fields.get("command").is_none()
            || fields.get("events").is_none()
        {
            return Err(refusal(level, " is not valid"));
        }
        if level.is_empty() {
            return Err(refusal(level, " is not valid"));
        }
        if !accepted_levels
            .iter()
            .any(|a| a.borrowed().points().eq(level.iter().copied()))
        {
            return Err(refusal(
                level,
                " is not among the trust levels this kind accepts",
            ));
        }
        let raw_events = fields.get("events");
        // Python builds set(events) before checking event membership.
        for member in raw_events.and_then(Source::array).into_iter().flatten() {
            let kind = match member.node() {
                Node::Array(_) => "list",
                Node::Object(_) => "dict",
                _ => continue,
            };
            return Err(exception(
                "TypeError",
                format!("cannot use '{kind}' as a set element (unhashable type: '{kind}')"),
            ));
        }
        let events = raw_events
            .and_then(value_source::names)
            .filter(|events| {
                events
                    .iter()
                    .all(|event| *event == "pull_request" || *event == "merge_group")
                    && (events.len() == 1 || (events.len() == 2 && events[0] != events[1]))
            })
            .map(|events| events.into_iter().map(|event| event.to_string()).collect())
            .ok_or_else(|| {
                rule_error(
                    &kind_context,
                    "events must be a nonempty list of pull_request, merge_group",
                )
            })?;
        let Value::Object(mut legacy_fields) = value_source::to_value(fields) else {
            return Err(refusal(level, " is not valid"));
        };
        let inputs = checked_command_inputs(
            &mut legacy_fields,
            &[
                check.text(),
                TextRef::Str("/"),
                TextRef::Str(kind),
                TextRef::Str("/"),
                TextRef::Points(level),
            ],
        )?;
        let lane = match fields.get("lane") {
            None => LaneBinding::None,
            Some(value) if value.as_bool() == Some(false) => LaneBinding::None,
            Some(value) if value.as_bool() == Some(true) => LaneBinding::Base,
            Some(value) if value.str_is("tree") => LaneBinding::Tree,
            _ => return Err(refusal(level, " lane must be true, false or \"tree\"")),
        };
        by_level.push((
            NormalizedText::from_points(level),
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

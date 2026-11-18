//! Complete legacy kind/level declarations; no record evaluation.
use super::check_names::CheckName;
use super::level_rules::{LevelRule, fill, normalized};
use super::normalized_text::NormalizedText;
use super::value_rules::ValueRules;
use super::value_source::{self, Source};
use super::{
    CommandInputs, PolicyError, base_source, command_source, exception, invalid, rule_error,
};
use crate::evidence::legacy_verify::statement_document::Node;
use crate::evidence::legacy_verify::{failure_json::TextRef, python_repr::Repr};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct KindRule {
    #[serde(flatten)]
    pub inputs: CommandInputs,
    pub runner_prefix: Option<NormalizedText>,
    pub trust_levels: Option<Vec<NormalizedText>>,
    #[serde(serialize_with = "super::level_rules::serialize_level_pairs")]
    pub by_level: Vec<(NormalizedText, LevelRule)>,
    #[serde(flatten)]
    pub values: ValueRules,
    #[serde(serialize_with = "super::serialize_pairs")]
    pub base_inputs: Vec<(NormalizedText, String)>,
}
pub fn checked_kinds<'a>(
    kinds: Source<'_>,
    levels: &[NormalizedText],
    repository: &str,
    check: impl Into<CheckName<'a>>,
) -> Result<Vec<(String, KindRule)>, PolicyError> {
    from_source(kinds, levels, repository, check.into())
}
pub(super) fn from_source(
    kinds: Source<'_>,
    levels: &[NormalizedText],
    repository: &str,
    check: CheckName<'_>,
) -> Result<Vec<(String, KindRule)>, PolicyError> {
    kinds
        .entries()
        .into_iter()
        .flatten()
        .map(|(kind, rule)| {
            let error = || {
                invalid(NormalizedText::around(
                    "skip policy for ",
                    check.text(),
                    &format!(": kind {} is not valid", Repr(TextRef::Points(kind))),
                ))
            };
            let kind = ["nix", "wrapper", "sekrets", "observed"]
                .into_iter()
                .find(|name| value_source::key_is(kind, name))
                .ok_or_else(error)?;
            if rule.object().is_none_or(|entries| {
                entries.keys().any(|key| {
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
                    .iter()
                    .any(|name| value_source::key_is(key, name))
                })
            }) || rule.get("command").is_none()
            {
                return Err(error());
            }
            let where_ = [check.text(), TextRef::Str("/"), TextRef::Str(kind)];
            let inputs = command_source(rule, &where_)?;
            let values = super::value_rules::from_source(rule, &where_)?;
            let base_inputs = base_source(rule, &where_)?;
            let trust_levels = match rule.get("trust_levels") {
                None => None,
                Some(value) if value.is_null() => None,
                Some(value) => Some(value_source::names(value).ok_or_else(|| {
                    rule_error(&where_, "trust_levels must be a nonempty list of names")
                })?),
            };
            let runner_prefix = match rule.get("runner_prefix") {
                None => None,
                Some(value) if value.is_null() => None,
                Some(value) => Some(fill(
                    value
                        .normalized()
                        .filter(|text| text.borrowed().points().next().is_some())
                        .ok_or_else(|| rule_error(&where_, "malformed runner_prefix"))?,
                    repository,
                    check,
                )),
            };
            let attribute = |kind| {
                exception(
                    "AttributeError",
                    format!("'{kind}' object has no attribute 'items'"),
                )
            };
            let overrides = rule.get("by_level");
            let overrides = match overrides {
                None => None,
                Some(value) => match value.node() {
                    Node::Object(_) => Some(value),
                    Node::Null | Node::Bool(false) => None,
                    Node::String(text) if text.is_empty() => None,
                    Node::Array(items) if items.is_empty() => None,
                    Node::Integer(decimal) if decimal == "0" => None,
                    Node::Float(number) if *number == 0.0 => None,
                    Node::Bool(true) => return Err(attribute("bool")),
                    Node::Integer(_) => return Err(attribute("int")),
                    Node::Float(_) => return Err(attribute("float")),
                    Node::String(_) => return Err(attribute("str")),
                    Node::Array(_) => return Err(attribute("list")),
                },
            };
            let by_level = match overrides {
                Some(overrides) => super::level_rules::from_source(
                    overrides,
                    trust_levels.as_deref().unwrap_or(levels),
                    repository,
                    check,
                    kind,
                )?,
                None => Vec::new(),
            };
            Ok((
                kind.to_owned(),
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
        let output = crate::pinned_python::command()
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

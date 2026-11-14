//! Legacy input-value ordering and shard declarations, not evidence judgments.
use super::{PolicyError, exception, names, rule_error};
use crate::evidence::legacy_verify::failure_json::TextRef;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashSet;

#[derive(Debug, Serialize)]
pub struct ValueRules {
    #[serde(serialize_with = "super::serialize_pairs")]
    pub input_order: Vec<(String, Vec<String>)>,
    pub shard_inputs: Option<ShardInputs>,
}
#[derive(Debug, Serialize)]
pub struct ShardInputs {
    pub count: String,
    pub results: String,
    /// Preserve absent versus explicit null in the normalized legacy schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request_count: Option<Option<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
}

/// Consume the two value-rule fields; outer kind key validation is separate.
pub fn checked_value_rules(
    rule: &mut Map<String, Value>,
    where_: &[TextRef<'_>],
) -> Result<ValueRules, PolicyError> {
    let order_error = || {
        rule_error(
            where_,
            "input_order maps an input to two or more distinct values, strongest first",
        )
    };
    let Value::Object(order) = rule
        .remove("input_order")
        .unwrap_or(Value::Object(Map::new()))
    else {
        return Err(order_error());
    };
    let mut input_order = Vec::with_capacity(order.len());
    for (key, value) in order {
        // Python builds set(v) before checking that every member is a string.
        if !key.is_empty()
            && let Some(values) = value.as_array().filter(|v| v.len() >= 2)
        {
            for item in values {
                let kind = match item {
                    Value::Array(_) => Some("list"),
                    Value::Object(_) => Some("dict"),
                    _ => None,
                };
                if let Some(kind) = kind {
                    return Err(exception(
                        "TypeError",
                        format!("cannot use '{kind}' as a set element (unhashable type: '{kind}')"),
                    ));
                }
            }
        }
        let values = names(value)
            .filter(|values| {
                values.len() >= 2 && values.iter().collect::<HashSet<_>>().len() == values.len()
            })
            .ok_or_else(order_error)?;
        if key.is_empty() {
            return Err(order_error());
        }
        input_order.push((key, values));
    }
    let shard_error = || {
        rule_error(
            where_,
            "shard_inputs needs count and results input names, an optional pull_request_count from 1 to 16 and an optional index input name",
        )
    };
    let shard_inputs = match rule.remove("shard_inputs") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let Value::Object(mut fields) = value else {
                return Err(shard_error());
            };
            if fields
                .keys()
                .any(|k| !["count", "results", "pull_request_count", "index"].contains(&k.as_str()))
            {
                return Err(shard_error());
            }
            let take_name = |value: Option<Value>| match value {
                Some(Value::String(value)) if !value.is_empty() => Some(value),
                _ => None,
            };
            let count = take_name(fields.remove("count")).ok_or_else(shard_error)?;
            let results = take_name(fields.remove("results")).ok_or_else(shard_error)?;
            let index = if fields.contains_key("index") {
                Some(take_name(fields.remove("index")).ok_or_else(shard_error)?)
            } else {
                None
            };
            let pull_request_count = match fields.remove("pull_request_count") {
                None => None,
                Some(Value::Null) => Some(None),
                Some(value) => Some(Some(
                    value
                        .as_u64()
                        .filter(|v| (1..=16).contains(v))
                        .ok_or_else(shard_error)?,
                )),
            };
            Some(ShardInputs {
                count,
                results,
                pull_request_count,
                index,
            })
        }
    };
    Ok(ValueRules {
        input_order,
        shard_inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn value_schemas_match_the_pinned_oracle() {
        let mut cases = vec![json!({}), json!({"unrelated":true})];
        let orders: Vec<Value> = serde_json::from_str(
            r#"[
          null, [], false, {}, {"": ["a","b"]}, {"mode":null}, {"mode":[]},
          {"mode":["a"]}, {"mode":["a","a"]}, {"mode":["a",""]}, {"mode":["a",1]},
          {"mode":[[],[]]}, {"mode":["strong","weak"]}, {"mode":["b","a","c"]},
          {"z":["a","b"],"a":["b","a"]}
        ]"#,
        )
        .unwrap();
        cases.extend(orders.into_iter().map(|order| json!({"input_order":order})));
        let shards: Vec<Value> = serde_json::from_str(
            r#"[
          null, [], false, {}, {"count":"n"}, {"results":"r"}, {"count":"n","results":"r"},
          {"count":"","results":"r"}, {"count":1,"results":"r"}, {"count":"n","results":null},
          {"count":"n","results":"r","extra":true}, {"count":"n","results":"r","index":"i"},
          {"count":"n","results":"r","index":null}, {"count":"n","results":"r","index":""},
          {"count":"n","results":"r","pull_request_count":null}
        ]"#,
        )
        .unwrap();
        cases.extend(
            shards
                .into_iter()
                .map(|shards| json!({"shard_inputs":shards})),
        );
        for count in [
            json!(1),
            json!(16),
            json!(0),
            json!(17),
            json!(-1),
            json!(true),
            json!(1.0),
            json!("1"),
        ] {
            cases.push(
                json!({"shard_inputs":{"count":"n","results":"r","pull_request_count":count}}),
            );
        }
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for rule in json.loads(sys.argv[2]):
    try:
        order, shards = oracle['checked_value_rules'](rule, 'fixture')
        results.append(dict(input_order=order, shard_inputs=shards))
    except (oracle['Failure'], TypeError):
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
            let actual = checked_value_rules(&mut fields, &[TextRef::Str("fixture")])
                .map(|rules| serde_json::to_value(rules).unwrap())
                .unwrap_or_else(|error| {
                    assert!(
                        matches!(
                            error.origin,
                            super::super::ErrorOrigin::Exception { class: "TypeError" }
                        ) || error
                            .detail
                            .to_string()
                            .starts_with("skip policy for fixture: ")
                    );
                    json!({"reason":error.reason})
                });
            assert_eq!(actual, expected, "{rule}");
        }
    }

    #[test]
    fn repeated_keys_keep_the_last_value_and_first_position() {
        let text = r#"{"command":["true"],
          "bind_inputs":{"z":"old","a":"middle","z":"last"},
          "base_inputs":{"z":"old.txt","a":"middle.txt","z":"last.txt"},
          "input_order":{"z":["old","weak"],"a":["middle","weak"],"z":["last","weak"]}}"#;
        let mut fields: Map<String, Value> = serde_json::from_str(text).unwrap();
        let command =
            super::super::checked_command_inputs(&mut fields, &[TextRef::Str("fixture")]).unwrap();
        let base =
            super::super::checked_base_inputs(&mut fields, &[TextRef::Str("fixture")]).unwrap();
        let values = checked_value_rules(&mut fields, &[TextRef::Str("fixture")]).unwrap();
        let actual = json!([command.bind_inputs, base, values.input_order]);
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle, rule = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify'), json.loads(sys.argv[2])
_, _, binds = oracle['checked_command_inputs'](rule, 'fixture')
base = oracle['checked_base_inputs'](rule, 'fixture')
order, _ = oracle['checked_value_rules'](rule, 'fixture')
print(json.dumps([list(value.items()) for value in (binds, base, order)]))
"#;
        let output = std::process::Command::new("python3")
            .args(["-c", script, &root, text])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(actual, expected);
        let retained = json!([
            [["z", "last"], ["a", "middle"]],
            [["z", "last.txt"], ["a", "middle.txt"]],
            [["z", ["last", "weak"]], ["a", ["middle", "weak"]]]
        ]);
        assert_eq!(actual, retained);
    }

    #[test]
    fn input_order_preserves_the_oracle_deciding_reason() {
        let rules = json!([
            {"input_order":{"z":["strong","weak"],"a":["strong","weak"]}},
            {"input_order":{"a":["strong","weak"],"z":["strong","weak"]}}
        ]);
        let parsed: Vec<_> = rules
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| {
                let mut fields = rule.as_object().unwrap().clone();
                serde_json::to_value(
                    checked_value_rules(&mut fields, &[TextRef::Str("fixture")]).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
reasons = []
for original, parsed in zip(json.loads(sys.argv[2]), json.loads(sys.argv[3])):
    for rule in (original, parsed):
        try:
            oracle['value_checks'](rule, {'z': 'wrong'}, {'z': 'strong'}, 1)
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
}

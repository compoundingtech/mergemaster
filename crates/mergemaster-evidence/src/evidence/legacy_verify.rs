//! Legacy policy evaluation, separate from native gate authorization.
pub mod events;
pub mod inputs;
pub mod lanes;
pub mod routing;
use super::legacy_policy::kind_rules::KindRule;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Failure {
    pub reason: &'static str,
    pub detail: String,
    pub attempts: usize,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}
impl std::error::Error for Failure {}

pub fn value_checks(
    rule: &KindRule,
    inputs: &BTreeMap<String, String>,
    run: &BTreeMap<String, String>,
    attempts: usize,
) -> Result<(), Failure> {
    let fail = |reason, key: &str| Failure {
        reason,
        detail: format!("input {key} does not cover this run"),
        attempts,
    };
    for (key, order) in &rule.values.input_order {
        let rank = |value| order.iter().position(|entry| Some(entry) == value);
        let run_rank = rank(run.get(key)).ok_or_else(|| fail("no_run_input", key))?;
        if rank(inputs.get(key)).is_none_or(|note_rank| note_rank > run_rank) {
            return Err(fail("wrong_input", key));
        }
    }
    for (key, _) in &rule.base_inputs {
        let expected = run
            .get(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fail("no_run_input", key))?;
        if inputs.get(key) != Some(expected) {
            return Err(fail("wrong_input", key));
        }
    }
    if let Some(shards) = &rule.values.shard_inputs {
        let count = inputs
            .get(&shards.count)
            .and_then(|value| shard_count(value))
            .ok_or_else(|| fail("wrong_input", &shards.count))?;
        let complete = inputs.get(&shards.results).is_some_and(|value| {
            let mut parts = value.split(',');
            (0..count).all(|index| {
                parts.next().is_some_and(|part| {
                    part.split_once('=').is_some_and(|(number, status)| {
                        status == "success"
                            && number.len() == if index < 10 { 1 } else { 2 }
                            && number.parse::<u8>().ok() == Some(index)
                    })
                })
            }) && parts.next().is_none()
        });
        if !complete
            || (inputs
                .get("event_name")
                .is_some_and(|event| event == "pull_request")
                && shards
                    .pull_request_count
                    .flatten()
                    .is_some_and(|expected| expected != u64::from(count)))
        {
            return Err(fail("wrong_input", &shards.results));
        }
    }
    Ok(())
}
fn shard_count(value: &str) -> Option<u8> {
    // unicode-shard-count: ordinary refusal, not Python's numeric conversion exceptions.
    if value.is_empty() || value.len() > 4300 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value
        .bytes()
        .try_fold(0_u8, |count, digit| {
            count
                .checked_mul(10)?
                .checked_add(digit - b'0')
                .filter(|count| *count <= 16)
        })
        .filter(|count| *count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::legacy_policy::PolicyDocument;
    use serde_json::{Value, json};
    #[test]
    fn value_judgments_and_shards_match_the_oracle() {
        let mut cases: Vec<Value> = serde_json::from_str(r#"[
          [{},{},{}],
          [{"input_order":{"z":["strong","weak"],"a":["strong","weak"]}},{"z":"bad"},{"z":"strong"}],
          [{"input_order":{"a":["strong","weak"],"z":["strong","weak"]}},{"z":"bad"},{"z":"strong"}],
          [{"input_order":{"x":["strong","weak"]}},{"x":"strong"},{"x":"weak"}],
          [{"input_order":{"x":["strong","weak"]}},{"x":"weak"},{"x":"strong"}],
          [{"input_order":{"x":["strong","weak"]}},{"x":"strong"},{"x":"strong"}],
          [{"input_order":{"x":["strong","weak"]}},{"x":"strong"},{"x":"bad"}],
          [{"base_inputs":{"z":"z","a":"a"}},{"z":"bad"},{"z":"expected"}],
          [{"base_inputs":{"a":"a","z":"z"}},{"z":"bad"},{"z":"expected"}],
          [{"base_inputs":{"x":"."}},{"x":"same"},{"x":"same"}],
          [{"base_inputs":{"x":"."}},{"x":"same"},{"x":""}]
        ]"#).unwrap();
        for count in ["1", "01", "0", "17", "", "-1", "1.0", "١", "１", "𝟙", "²"] {
            cases.push(json!([{"shard_inputs":{"count":"n","results":"r"}},{"n":count,"r":"0=success"},{}]));
        }
        for length in [4300, 4301] {
            cases.push(json!([{"shard_inputs":{"count":"n","results":"r"}},
                {"n":format!("{}1","0".repeat(length - 1)),"r":"0=success"},{}]));
        }
        for results in [
            "0=success,1=success",
            "1=success,0=success",
            "0=success",
            "0=success,1=failure",
            "00=success,1=success",
            "0=success,1=success,",
        ] {
            cases.push(
                json!([{"shard_inputs":{"count":"n","results":"r","pull_request_count":2}},
                {"n":"2","r":results,"event_name":"pull_request"},{}]),
            );
        }
        for event in ["pull_request", "merge_group"] {
            cases.push(
                json!([{"shard_inputs":{"count":"n","results":"r","pull_request_count":2}},
                {"n":"1","r":"0=success","event_name":event},{}]),
            );
        }
        let all_shards = (0..16)
            .map(|index| format!("{index}=success"))
            .collect::<Vec<_>>()
            .join(",");
        cases.push(
            json!([{"shard_inputs":{"count":"n","results":"r","pull_request_count":null}},
            {"n":"16","r":all_shards,"event_name":"pull_request"},{}]),
        );
        cases.push(json!([{"shard_inputs":{"count":"n","results":"r"}},{"r":"0=success"},{}]));
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for rule, inputs, run in json.loads(sys.argv[2]):
    try:
        oracle['value_checks'](rule, inputs, run, 7)
        results.append(dict(reason='satisfied'))
    except oracle['Failure'] as failure:
        results.append(dict(reason=failure.reason, attempts=failure.extra['attempts']))
    except ValueError:
        results.append(dict(reason='ValueError'))
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
        for (case, expected) in cases.iter().zip(expected) {
            let mut rule = case[0].clone();
            rule["command"] = json!(["true"]);
            let policy = json!({"version":1,"checks":{"check":{"trust_levels":["agent"],"kinds":{"wrapper":rule}}}});
            let rules = PolicyDocument::parse(&policy.to_string(), "check")
                .unwrap()
                .into_rules("owner/repo")
                .unwrap();
            let inputs = serde_json::from_value(case[1].clone()).unwrap();
            let run = serde_json::from_value(case[2].clone()).unwrap();
            let actual = value_checks(&rules.kinds[0].1, &inputs, &run, 7)
                .map(|()| json!({"reason":"satisfied"}))
                .unwrap_or_else(|failure| {
                    assert!(!failure.detail.is_empty());
                    json!({"reason":failure.reason,"attempts":failure.attempts})
                });
            let count = inputs.get("n").map(String::as_str).unwrap_or("");
            if matches!(count, "١" | "１" | "𝟙" | "²") || count.len() > 4300 {
                assert_eq!(actual, json!({"reason":"wrong_input","attempts":7}));
                assert_eq!(
                    expected["reason"],
                    if matches!(count, "²") || count.len() > 4300 {
                        "ValueError"
                    } else {
                        "satisfied"
                    }
                );
            } else {
                assert_eq!(actual, expected, "{case}");
            }
        }
    }
}

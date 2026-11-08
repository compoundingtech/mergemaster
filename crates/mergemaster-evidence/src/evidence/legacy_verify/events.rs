//! Legacy event intersections and shard-part classification.
use crate::evidence::legacy_policy::PolicyRules;
use std::collections::BTreeMap;
pub fn narrowed_events<'a>(
    check: Option<&'a [String]>,
    level: Option<&'a [String]>,
) -> Option<Vec<&'a str>> {
    match (check, level) {
        (None, None) => None,
        (Some(events), None) | (None, Some(events)) => {
            Some(events.iter().map(String::as_str).collect())
        }
        (Some(check), Some(level)) => Some(
            level
                .iter()
                .filter(|event| check.contains(event))
                .map(String::as_str)
                .collect(),
        ),
    }
}
pub fn kind_of(runner: &str) -> Option<&'static str> {
    match runner {
        "nix" => Some("nix"),
        "wrapper" => Some("wrapper"),
        "sekrets" => Some("sekrets"),
        _ if runner.starts_with("github:") => Some("observed"),
        _ => None,
    }
}
pub fn shard_part(
    rules: Option<&PolicyRules>,
    runner: &str,
    inputs: &BTreeMap<String, String>,
) -> bool {
    let Some(kind) = kind_of(runner) else {
        return false;
    };
    rules
        .and_then(|rules| rules.kinds.iter().find(|(name, _)| name == kind))
        .and_then(|(_, rule)| rule.values.shard_inputs.as_ref())
        .and_then(|shards| shards.index.as_ref())
        .and_then(|index| inputs.get(index))
        .is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::legacy_policy::PolicyDocument;
    use serde_json::{Value, json};
    #[test]
    fn event_intersection_and_shard_parts_match_the_oracle() {
        let policy = r#"{"version":1,"checks":{"check":{"trust_levels":["agent"],"kinds":{
          "wrapper":{"command":["true"],"shard_inputs":{"count":"n","results":"r","index":"i"}},
          "observed":{"command":["true"]}}}}}"#;
        let rules = PolicyDocument::parse(policy, "check")
            .unwrap()
            .into_rules("owner/repo")
            .unwrap();
        let events = [
            None,
            Some(vec!["pull_request".to_owned()]),
            Some(vec!["merge_group".to_owned(), "pull_request".to_owned()]),
            Some(vec!["merge_group".to_owned()]),
            Some(vec!["pull_request".to_owned(), "merge_group".to_owned()]),
            Some(vec![]),
            Some(vec!["pull_request".to_owned(), "pull_request".to_owned()]),
        ];
        let mut actual = Vec::new();
        for check in &events {
            for level in &events {
                actual.push(json!(narrowed_events(check.as_deref(), level.as_deref())));
            }
        }
        for runner in [
            "wrapper",
            "nix",
            "sekrets",
            "github:",
            "github:job",
            "github",
            "other",
            "Wrapper",
            "GITHUB:x",
        ] {
            for value in [None, Some(""), Some("0"), Some("1"), Some(" ")] {
                let inputs = value
                    .map(|v| BTreeMap::from([("i".into(), v.into())]))
                    .unwrap_or_default();
                actual.push(json!([
                    kind_of(runner),
                    shard_part(Some(&rules), runner, &inputs),
                    shard_part(None, runner, &inputs)
                ]));
            }
        }
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
rules = oracle['policy_rules'](sys.argv[2], 'check', 'owner/repo')
events = [None, ['pull_request'], ['merge_group', 'pull_request'], ['merge_group'], ['pull_request', 'merge_group'], [], ['pull_request', 'pull_request']]
actual = [oracle['narrowed_events'](check, level) for check in events for level in events]
for runner in ('wrapper', 'nix', 'sekrets', 'github:', 'github:job', 'github', 'other', 'Wrapper', 'GITHUB:x'):
    for value in (None, '', '0', '1', ' '):
        statement = dict(predicate=dict(observed=dict(runner=runner, inputs={} if value is None else dict(i=value))))
        actual.append([oracle['kind_of'](runner), oracle['shard_part'](rules, statement), oracle['shard_part'](None, statement)])
print(json.dumps(actual))
"#;
        let output = std::process::Command::new("python3")
            .args(["-c", script, &root, policy])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(actual, expected);
    }
}

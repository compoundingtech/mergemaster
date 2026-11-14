//! Legacy event intersections and shard-part classification.
use super::value_inputs::{InputSource, TextRef};
use crate::evidence::legacy_policy::PolicyRules;
use std::collections::BTreeMap;
pub fn narrowed_events<'a>(
    check: Option<&'a [String]>,
    level: Option<&'a [String]>,
) -> Option<Vec<&'a str>> {
    narrowed_event_iter(check, level).map(Iterator::collect)
}
/// Preserve None versus an empty intersection and borrow the level's ordered entries.
pub(super) fn narrowed_event_iter<'a>(
    check: Option<&'a [String]>,
    level: Option<&'a [String]>,
) -> Option<impl Iterator<Item = &'a str>> {
    Some(
        level
            .or(check)?
            .iter()
            .filter(move |event| level.is_none() || check.is_none_or(|check| check.contains(event)))
            .map(String::as_str),
    )
}
pub fn kind_of(runner: &str) -> Option<&'static str> {
    kind_of_text(TextRef::Str(runner))
}
pub(super) fn kind_of_text(runner: TextRef<'_>) -> Option<&'static str> {
    ["nix", "wrapper", "sekrets"]
        .into_iter()
        .find(|kind| runner.equals(kind))
        .or_else(|| runner.starts_with("github:").then_some("observed"))
}
pub fn shard_part(
    rules: Option<&PolicyRules>,
    runner: &str,
    inputs: &BTreeMap<String, String>,
) -> bool {
    shard_part_source(rules, TextRef::Str(runner), &InputSource::Native(inputs))
}
pub(super) fn shard_part_source(
    rules: Option<&PolicyRules>,
    runner: TextRef<'_>,
    inputs: &InputSource<'_>,
) -> bool {
    let Some(kind) = kind_of_text(runner) else {
        return false;
    };
    rules
        .and_then(|rules| rules.kinds.iter().find(|(name, _)| name == kind))
        .and_then(|(_, rule)| rule.values.shard_inputs.as_ref())
        .and_then(|shards| shards.index.as_ref())
        .and_then(|index| inputs.get_text(index.borrowed()))
        .is_some_and(|value| value.len() != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::legacy_policy::PolicyDocument;
    use serde_json::{Value, json};
    #[test]
    fn lazy_intersection_borrows_the_ordered_source() {
        let check = ["pull_request".to_owned(), "merge_group".to_owned()];
        let level = ["merge_group".to_owned(), "pull_request".to_owned()];
        let mut narrowed = narrowed_event_iter(Some(&check), Some(&level)).unwrap();
        assert!(std::ptr::eq(narrowed.next().unwrap(), level[0].as_str()));
        assert!(std::ptr::eq(narrowed.next().unwrap(), level[1].as_str()));
        assert!(narrowed.next().is_none());
        assert!(narrowed_event_iter(None, None).is_none());
    }
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

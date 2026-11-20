use super::*;
use crate::evidence::legacy_policy::{PolicyDocument, PolicyRules};
use serde_json::{Value, json};

fn summary(rules: &PolicyRules) -> Value {
    let kind = &rules.kinds[0].1;
    let command = |command: &[super::super::normalized_text::NormalizedText]| {
        command
            .iter()
            .map(|text| text.borrowed().points().collect::<Vec<_>>())
            .collect::<Vec<_>>()
    };
    json!({"require":rules.header.require,"command":command(&kind.inputs.command),
        "prefix":kind.runner_prefix.as_ref().map(|text| text.borrowed().points().collect::<Vec<_>>()),
        "level_command":command(&kind.by_level[0].1.inputs.command)})
}
#[test]
fn lossless_policy_names_normalize_through_the_pinned_rules() {
    let frozen = include_bytes!(
        "../../../../../tests/fixtures/oracle/policy-helpers/lossless-policy-names-normalize-through-the-pinned-rules/stdout.bin"
    );
    let cases: Vec<Value> = serde_json::from_slice(frozen).unwrap();
    assert_eq!(cases.len(), 82);
    for case in cases {
        if let Some(raw) = case.get("policy_bytes") {
            let bytes: Vec<u8> = serde_json::from_value(raw.clone()).unwrap();
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), bytes).unwrap();
            assert_eq!(
                std::fs::read_to_string(file.path()).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(case["reason"], "no_policy");
            continue;
        }
        let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
        let text = case["text"].as_str().unwrap();
        let repo = case["repo"].as_str().unwrap();
        let document = PolicyDocument::parse(text, check.as_slice()).unwrap();
        let TextRef::Points(borrowed) = document.check.text() else {
            panic!("not borrowed points")
        };
        assert!(std::ptr::eq(borrowed, check.as_slice()));
        let actual = document
            .into_rules(repo)
            .map(|rules| summary(&rules))
            .unwrap_or_else(|e| json!({"reason":e.reason}));
        assert_eq!(actual, case["expected"], "{case}");
        if let Some(scalar) = check
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
        {
            let scalar_result = PolicyDocument::parse(text, scalar.as_str())
                .unwrap()
                .into_rules(repo)
                .map(|rules| summary(&rules))
                .unwrap_or_else(|e| json!({"reason":e.reason}));
            assert_eq!(scalar_result, actual, "scalar API changed");
        }
    }
}

#[test]
fn nested_policy_text_keeps_python_point_identity() {
    let frozen = include_bytes!(
        "../../../../../tests/fixtures/oracle/policy-helpers/nested-policy-text-keeps-python-point-identity/stdout.bin"
    );
    let cases: Vec<Value> = serde_json::from_slice(frozen).unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let rules = PolicyDocument::parse(case["text"].as_str().unwrap(), name.as_slice())
            .unwrap()
            .into_rules("org/repo")
            .unwrap();
        let points = |text: &super::super::normalized_text::NormalizedText| {
            text.borrowed().points().collect::<Vec<_>>()
        };
        let kind = &rules.kinds[0].1;
        let (level, rule) = &kind.by_level[0];
        let shard = kind.values.shard_inputs.as_ref().unwrap();
        let actual = json!({
            "level":points(&rules.header.trust_levels[0]),
            "command":kind.inputs.command.iter().map(points).collect::<Vec<_>>(),
            "required":kind.inputs.required_inputs.iter().map(points).collect::<Vec<_>>(),
            "bind":kind.inputs.bind_inputs.iter().map(|(a,b)| (points(a),points(b))).collect::<Vec<_>>(),
            "order":kind.values.input_order.iter().map(|(a,bs)| (points(a),bs.iter().map(points).collect::<Vec<_>>())).collect::<Vec<_>>(),
            "base":kind.base_inputs.iter().map(|(a,b)| (points(a),b)).collect::<Vec<_>>(),
            "shard":[points(&shard.count),points(&shard.results),points(shard.index.as_ref().unwrap())],
            "by_level":points(level),
            "level_command":rule.inputs.command.iter().map(points).collect::<Vec<_>>(),
            "level_required":rule.inputs.required_inputs.iter().map(points).collect::<Vec<_>>(),
            "level_bind":rule.inputs.bind_inputs.iter().map(|(a,b)| (points(a),points(b))).collect::<Vec<_>>()
        });
        assert_eq!(actual, case["expected"]);
    }
}

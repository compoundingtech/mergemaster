use super::*;
use crate::evidence::{
    legacy_policy::{PolicyDocument, PolicyError},
    legacy_verify::{
        candidates::{Candidate, LaneOnce, Levels},
        facts::DocumentFacts,
        judgment::{LaneDefinition, Provider},
        ordering::CheckJudgment,
        statement::statement_of,
    },
};
use serde_json::{Value, json};
#[test]
fn result_dictionary_fields_match_python() {
    let fixtures = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/judgment-core/result-dictionary/stdout.bin"
    ));
    let fixtures = fixtures.as_array().unwrap();
    assert_eq!(fixtures.len(), 435);
    struct NoGit;
    impl Provider for NoGit {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            panic!("no lane required")
        }
        fn blob_sha256(
            &mut self,
            _: crate::evidence::legacy_verify::judgment::BindingPath<'_>,
        ) -> Result<Option<String>, PolicyError> {
            panic!("no bindings")
        }
    }
    let wire_names = [
        None,
        Some(&[0xd800][..]),
        Some(&[102, 97, 99, 101, 0x1f600][..]),
    ];
    let wire_skips = ["other host level_not_accepted".to_owned()];
    let mut wire_cases = 0;
    for observation in fixtures {
        let fixture = crate::oracle_digest::json(&observation["input"]);
        let policy = fixture["policy"].as_str().map(|policy| {
            PolicyDocument::parse(policy, "unit")
                .unwrap()
                .into_rules("owner/repo")
                .unwrap()
        });
        let document = statement_of(
            fixture["statement"].as_str().unwrap().as_bytes(),
            fixture["matched"].as_str().unwrap(),
        )
        .unwrap()
        .unwrap();
        let facts = DocumentFacts::for_check(
            &document,
            &[117, 110, 105, 116],
            fixture["principal"].as_str().unwrap(),
        )
        .unwrap();
        let candidates = vec![Candidate {
            commit: "record",
            facts,
        }];
        let kinds = vec!["wrapper".chars().map(u32::from).collect()];
        let options = super::super::judgment::Unconfigured {
            routing: super::super::routing::Unconfigured {
                kinds: &kinds,
                trust_levels: None,
                runner_prefix: None,
            },
            command: None,
            max_age: fixture["age"]
                .as_u64()
                .map(super::super::inputs::AgeLimit::Seconds),
            bindings: &[],
        };
        let prepared = match &policy {
            Some(policy) => Prepared::new(policy, candidates, "unit").unwrap(),
            None => Prepared::unconfigured(&options, candidates),
        };
        let decision = CheckJudgment {
            clock: &mut 1_767_225_900_000_000i64,
            run_inputs: &std::collections::BTreeMap::new(),
            lane: None,
            provider: LaneOnce::new(NoGit),
        }
        .select(&prepared, "unit", Levels::Utf8(&[]));
        if let Ok((_, routing)) = &decision.result {
            assert_eq!(routing.is_none(), policy.is_none());
        }
        let actual = match Satisfied::from_decision(
            &prepared,
            &decision,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "unit",
            fixture["source"].as_str(),
        ) {
            Err(ViewError::Judgment(error)) => {
                assert!(std::ptr::eq(error, decision.result.as_ref().err().unwrap()));
                json!({"reason":error.reason})
            }
            Err(ViewError::InvalidDecision) => panic!("invalid fixture decision"),
            Ok(mut result) => {
                let original = (result.decided_by, result.skipped_newer);
                for (index, name) in wire_names.iter().enumerate() {
                    for mode in 0..3 {
                        result.check = name.map_or_else(|| "unit".into(), Into::into);
                        result.decided_by = if mode == 0 { None } else { original.0 };
                        result.skipped_newer = match mode {
                            0 => None,
                            1 => original.1,
                            _ => Some(&wire_skips),
                        };
                        let mut bytes = String::new();
                        crate::evidence::legacy_output::write(&mut bytes, |w| result.write_json(w))
                            .unwrap();
                        crate::oracle_digest::assert_value(
                            &Value::String(bytes),
                            &observation["wire"][index * 3 + mode],
                        );
                        wire_cases += 1;
                    }
                }
                result.check = "unit".into();
                (result.decided_by, result.skipped_newer) = original;
                assert!(std::ptr::eq(result.tier, prepared.candidates[0].facts.tier));
                assert!(
                    result
                        .command()
                        .zip(prepared.candidates[0].facts.command())
                        .all(|(a, b)| std::ptr::eq(a, b))
                );
                json!({
                    "satisfied":result.satisfied,"tree":result.tree,"check":result.check.to_string(),"record":result.record,
                    "kind":result.kind,"signer":result.signer,"trust_level":result.trust_level,"tier":result.tier,
                    "observed_at":result.observed_at,"command":result.command().collect::<Vec<_>>(),
                    "inputs":result.inputs().collect::<Vec<_>>(),"attempts":result.attempts,"policy":result.policy,
                    "max_age_s":result.max_age_s,"enforce":result.enforce,"match":result.r#match,
                    "matched_tree":result.matched_tree,"source_inputs":result.source_inputs,"sample_one_in":result.sample_one_in,
                    "events":result.events().map(|events|events.collect::<Vec<_>>()),
                    "decided_by":result.decided_by,"skipped_newer":result.skipped_newer
                })
            }
        };
        crate::oracle_digest::assert_value(&actual, &observation["expected"]);
    }
    assert_eq!(wire_cases, 3888);
}

#[test]
fn malformed_manual_success_decisions_return_a_textless_typed_error() {
    use super::super::{
        inputs::AgeLimit,
        ordering::{Decision, Walk},
    };
    for mode in [
        "subject", "empty", "digest", "tree", "index", "walk", "age", "kind",
    ] {
        let mut raw = json!({
            "subject":[{"digest":{"gitTree":"tree"}}],
            "predicate":{"tier":"full","observed_at":"2026-01-01T00:00:00Z",
                "observed":{"runner":"wrapper","checks":{"unit":{"exit_code":0,"command":["true"]}}}}
        });
        match mode {
            "subject" => raw["subject"] = Value::Null,
            "empty" => raw["subject"] = json!([]),
            "digest" => raw["subject"][0]["digest"] = Value::Null,
            "tree" => raw["subject"][0]["digest"]["gitTree"] = Value::Bool(false),
            "kind" => raw["predicate"]["observed"]["runner"] = json!("other"),
            _ => {}
        }
        let doc =
            super::super::statement_document::Document::from_bytes(raw.to_string().as_bytes())
                .unwrap();
        let name: Vec<_> = "unit".chars().map(u32::from).collect();
        let facts =
            super::super::facts::DocumentFacts::for_check(&doc, &name, "agent/fixture").unwrap();
        let kinds = vec!["wrapper".chars().map(u32::from).collect()];
        let options = super::super::judgment::Unconfigured {
            routing: super::super::routing::Unconfigured {
                kinds: &kinds,
                trust_levels: None,
                runner_prefix: None,
            },
            command: None,
            max_age: (mode == "age").then_some(AgeLimit::Overflow),
            bindings: &[],
        };
        let prepared = Prepared::unconfigured(
            &options,
            vec![super::super::candidates::Candidate {
                commit: "record",
                facts,
            }],
        );
        let decision = Decision {
            result: Ok((if mode == "index" { usize::MAX } else { 0 }, None)),
            walk: Walk {
                decided_by: (mode == "walk").then_some(usize::MAX),
                skipped_newer: vec![],
            },
        };
        assert!(
            matches!(
                Satisfied::from_decision(&prepared, &decision, "tree", "unit", None),
                Err(ViewError::InvalidDecision)
            ),
            "{mode}"
        );
    }
}

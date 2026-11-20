use super::*;
use crate::evidence::{legacy_policy::PolicyDocument, legacy_verify::statement_document::Document};
use serde_json::{Value, json};

#[test]
fn candidate_prelude_matches_python() {
    let policy = r#"{"version":1,"checks":{"unit":{"trust_levels":["agent"],"kinds":{
      "wrapper":{"command":["true"],"shard_inputs":{"count":"n","results":"r","index":"i"}},
      "nix":{"command":["true"],"trust_levels":["host"]}}}}}"#;
    let rules = PolicyDocument::parse(policy, "unit")
        .unwrap()
        .into_rules("owner/repo")
        .unwrap();
    let mut cases = Vec::new();
    for runner in ["wrapper", "nix", "unknown"] {
        for exit in ["0", "-1", "999999999999999999999999999999999999"] {
            for index in [None, Some(""), Some("0"), Some("\\ud800")] {
                // The capture uses lexical key order. Insert keys in that order too so
                // regeneration is identical with or without serde_json/preserve_order.
                let mut statement = json!({"predicate":{"observed":{"checks":{"unit":{"command":["true"],"exit_code":0}},
                    "inputs":{},"runner":runner},"observed_at":"2026-01-01T00:00:00Z","tier":"full"}});
                if let Some(index) = index {
                    statement["predicate"]["observed"]["inputs"]["i"] = json!(index);
                }
                let text = statement
                    .to_string()
                    .replace("\"exit_code\":0", &format!("\"exit_code\":{exit}"))
                    .replace("\\\\ud800", "\\ud800");
                // Duplicate entries preserve input order and count, including duplicate shard parts.
                cases.push(vec![text.clone(), text]);
            }
        }
    }
    cases.push(vec![
        cases[2][0].clone(),
        cases[0][0].clone(),
        cases[6][0].clone(),
    ]);
    let mut actual = Vec::new();
    for case in &cases {
        let docs: Vec<_> = case
            .iter()
            .map(|s| Document::from_bytes(s.as_bytes()).unwrap())
            .collect();
        let candidates = docs
            .iter()
            .enumerate()
            .map(|(i, document)| Candidate {
                commit: if i == 0 { "a" } else { "b" },
                facts: DocumentFacts::for_check(document, &[117, 110, 105, 116], "agent/key")
                    .unwrap(),
            })
            .collect();
        actual.push(match Prepared::new(&rules, candidates, "unit") {
            Ok(prepared) => {
                let Levels::Policy(accepted) = prepared.accepted_levels() else {
                    unreachable!()
                };
                let mut accepted: Vec<String> = accepted.iter().map(|a| a.to_string()).collect();
                // The oracle reports sorted(set(...)); model set semantics here.
                accepted.sort();
                accepted.dedup();
                json!({"commits":prepared.candidates.iter().map(|c| c.commit).collect::<Vec<_>>(),
                "attempts":prepared.attempts(),
                "accepted":accepted})
            }
            Err(failure) => {
                json!({"reason":failure.reason,"detail":failure.detail,"attempts":failure.attempts})
            }
        });
    }
    assert_eq!(
        serde_json::to_string(&(policy, &cases)).unwrap().as_bytes(),
        include_bytes!(
            "../../../../../tests/fixtures/oracle/judgment-core/candidate-prelude/stdin.json"
        ),
    );
    assert_eq!(
        actual,
        serde_json::from_slice::<Vec<Value>>(include_bytes!(
            "../../../../../tests/fixtures/oracle/judgment-core/candidate-prelude/stdout.bin"
        ))
        .unwrap()
    );
}

#[test]
fn shard_part_no_record_detail_matches_pinned_handlers_losslessly() {
    use crate::evidence::{
        legacy_output, legacy_policy::ErrorOrigin, legacy_verify::failure_json::WireError,
    };
    let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/judgment-core/shard-part-no-record/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let rules = PolicyDocument::parse(case["policy"].as_str().unwrap(), name.as_slice())
            .unwrap()
            .into_rules("owner/repo")
            .unwrap();
        let document =
            Document::from_bytes(case["statement"].as_str().unwrap().as_bytes()).unwrap();
        let candidates = vec![Candidate {
            commit: "a",
            facts: DocumentFacts::for_check(&document, &name, "agent/key").unwrap(),
        }];
        let error = match Prepared::new(&rules, candidates, name.as_slice()) {
            Ok(_) => panic!("expected shard-part no-record refusal"),
            Err(error) => error,
        };
        assert_eq!(error.reason, "no_record");
        assert_eq!(error.origin, ErrorOrigin::Failure);
        assert_eq!(error.attempts, Some(1));
        assert_eq!(
            serde_json::json!(error.detail.borrowed().points().collect::<Vec<_>>()),
            case["detail"]
        );
        let view = WireError::from_failure(&error, None, None);
        let mut single = String::new();
        legacy_output::write(&mut single, |w| view.write_json(name.as_slice().into(), w)).unwrap();
        assert_eq!(single, case["single"]);
        let mut global = String::new();
        legacy_output::write(&mut global, |w| view.write_global(w)).unwrap();
        assert_eq!(global, case["global_"]);
    }
}

#[test]
fn lane_once_caches_success_and_absence_but_not_errors() {
    use std::{cell::Cell, rc::Rc};
    struct Source {
        calls: Rc<Cell<usize>>,
        mode: u8,
        lane: Option<LaneDefinition>,
    }
    impl Provider for Source {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            self.calls.set(self.calls.get() + 1);
            if self.mode == 1 {
                Err(PolicyError {
                    resource: None,
                    origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                    reason: "error",
                    detail: "lane refused".into(),
                })
            } else {
                Ok(self.lane.as_ref())
            }
        }
        fn blob_sha256(
            &mut self,
            _: crate::evidence::legacy_verify::judgment::BindingPath<'_>,
        ) -> Result<Option<String>, PolicyError> {
            self.calls.set(self.calls.get() + 1);
            Ok(None)
        }
    }
    for mode in [0, 1, 2] {
        let calls = Rc::new(Cell::new(0));
        let mut provider = LaneOnce::new(Source {
            calls: calls.clone(),
            mode,
            lane: (mode == 2).then(|| LaneDefinition {
                sha256: "base".into(),
                changed: vec![b"path".to_vec()],
                tree_sha256: "tree".into(),
            }),
        });
        assert_eq!(calls.get(), 0);
        for _ in 0..3 {
            let result = provider.level_lane();
            assert_eq!(result.is_err(), mode == 1);
            if mode == 2 {
                let lane = result.unwrap().unwrap();
                assert_eq!(
                    (&*lane.sha256, &lane.changed, &*lane.tree_sha256),
                    ("base", &vec![b"path".to_vec()], "tree")
                );
            }
        }
        assert_eq!(calls.get(), if mode == 1 { 3 } else { 1 });
        provider
            .blob_sha256(super::super::judgment::BindingPath::Native(
                std::path::Path::new("a"),
            ))
            .unwrap();
        provider
            .blob_sha256(super::super::judgment::BindingPath::Native(
                std::path::Path::new("a"),
            ))
            .unwrap();
        assert_eq!(calls.get(), if mode == 1 { 5 } else { 3 });
    }
}

#[test]
fn borrowed_level_views_match_pinned_membership() {
    let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/judgment-core/borrowed-level-membership/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.len(), 49);
    for case in cases {
        let levels: Option<Vec<Vec<u32>>> = serde_json::from_value(case["levels"].clone()).unwrap();
        let query = case["query"].as_str().unwrap();
        let accepted = levels
            .as_deref()
            .map_or(Levels::Unrestricted, Levels::Codepoints);
        assert_eq!(json!(accepted.contains(query)), case["accepted"]);
        let preferred = Levels::Codepoints(levels.as_deref().unwrap_or(&[]));
        assert_eq!(json!(preferred.contains(query)), case["preferred"]);
        if let Some(points) = &levels {
            let native: Option<Vec<String>> = points
                .iter()
                .map(|points| points.iter().map(|&p| char::from_u32(p)).collect())
                .collect();
            if let Some(native) = native {
                let set: Vec<_> = native
                    .iter()
                    .map(|t| super::TextRef::Str(t.as_str()))
                    .collect();
                assert_eq!(
                    Levels::Utf8(&native).contains(query),
                    preferred.contains(query)
                );
                assert_eq!(
                    Levels::Policy(&set).contains(query),
                    preferred.contains(query)
                );
            }
        }
    }
}

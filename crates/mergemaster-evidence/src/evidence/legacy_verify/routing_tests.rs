use super::*;
use crate::evidence::legacy_policy::PolicyDocument;
use serde_json::json;

#[test]
fn lossless_routing_matches_the_pinned_judge_prefix() {
    let cases = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/judgment-core/routing/stdout.bin"
    ));
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 468);
    for observation in cases {
        let case = crate::oracle_digest::json(&observation["input"]);
        let doc = super::super::statement_document::Document::from_bytes(
            case["raw"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let principal = case["principal"].as_str().unwrap_or("agent/alice");
        let facts = DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], principal).unwrap();
        let actual = if case["policy"].is_null() {
            let kinds: Vec<Vec<u32>> = serde_json::from_value(case["kinds"].clone()).unwrap();
            let levels: Option<Vec<Vec<u32>>> = serde_json::from_value(case["levels"].clone()).unwrap();
            let prefix: Option<Vec<u32>> = serde_json::from_value(case["prefix"].clone()).unwrap();
            route_unconfigured(Unconfigured {
                kinds: &kinds, trust_levels: levels.as_deref(), runner_prefix: prefix.as_deref(),
            }, &facts, 7).map(|()| json!({"reason":"satisfied","command":null,"required":[],"bind":[],"events":null}))
        } else {
            let rules = PolicyDocument::parse(case["policy"].as_str().unwrap(), "check")
                .unwrap().into_rules("owner/repo").unwrap();
            route_document(&rules, &facts, 7).and_then(|routing| {
                routing.check_document_runner(facts.runner, 7)?;
                Ok(json!({"reason":"satisfied","command":routing.command_inputs.command,
                    "required":routing.command_inputs.required_inputs,"bind":routing.command_inputs.bind_inputs,
                    "events":routing.level.map(|level| &level.events)}))
            })
        }.unwrap_or_else(|failure| {
            assert_eq!(failure.origin, crate::evidence::legacy_policy::ErrorOrigin::Failure);
            json!({"reason":failure.reason,"attempts":failure.attempts,
                "detail":failure.detail.borrowed().points().collect::<Vec<_>>()})
        });
        crate::oracle_digest::assert_value(&actual, &observation["expected"]);
    }
}

#[test]
fn policy_routes_always_supply_the_resolved_kind_and_level_inputs() {
    let policy = PolicyDocument::parse(
        r#"{"version":1,"checks":{"check":{"trust_levels":["agent","host"],
        "kinds":{"wrapper":{"command":["true"],
        "by_level":{"agent":{"command":["override"],"events":["pull_request"]}}}}}}}"#,
        "check",
    )
    .unwrap()
    .into_rules("owner/repo")
    .unwrap();
    let check = Check {
        command: vec!["true".into()],
        exit_code: 0,
        output_sha256: String::new(),
    };
    let inputs = BTreeMap::new();
    let doc = super::super::statement_document::Document::from_bytes(
        br#"{"predicate":{"tier":"full","observed_at":"2026-01-01T00:00:00Z",
        "observed":{"runner":"wrapper","checks":{"check":{"exit_code":0,"command":["true"]}}}}}"#,
    )
    .unwrap();
    for (principal, expected, overridden) in [
        ("agent/alice", "override", true),
        ("host/alice", "true", false),
    ] {
        let native = route(
            &policy,
            &RecordFacts {
                check_name: "check".into(),
                tier: TrustTier::Full,
                runner: "wrapper",
                principal,
                check: &check,
                inputs: &inputs,
            },
            7,
        )
        .unwrap();
        let facts = DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], principal).unwrap();
        let document = route_document(&policy, &facts, 7).unwrap();
        for routing in [native, document] {
            assert!(std::ptr::eq(routing.kind, &policy.kinds[0].1));
            assert_eq!(routing.level.is_some(), overridden);
            assert_eq!(routing.command_inputs.command, [expected]);
        }
    }
}

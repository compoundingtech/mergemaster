use super::*;
use serde_json::{Value, json};

#[test]
fn selected_document_facts_match_the_oracle() {
    let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/judgment-core/document-facts/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.len(), 34);
    for case in cases {
        let doc = super::super::statement::statement_of(
            case["raw"].as_str().unwrap().as_bytes(),
            &"a".repeat(40),
        )
        .unwrap()
        .expect("oracle-valid statement");
        let key: Vec<u32> = serde_json::from_value(case["key"].clone()).unwrap();
        let actual = DocumentFacts::for_check(&doc, &key, case["principal"].as_str().unwrap()).map(|facts| {
            let inputs = facts.inputs.map(|inputs| inputs.iter().map(|(key,value)| json!([key,value])).collect::<Vec<_>>());
            json!({"tier":facts.tier,"runner":facts.runner,"principal":facts.principal,
                "exit_code":facts.exit_code,"observed_at":facts.observed_at,"moment_micros":facts.moment_micros,
                "failed":facts.failed(),"level":facts.level(),"command":facts.command().collect::<Vec<_>>(),"inputs":inputs})
        });
        assert_eq!(actual.unwrap_or(Value::Null), case["expected"], "{case}");
    }
}

#[test]
fn document_facts_do_not_panic_on_ill_shaped_views() {
    let base = json!({"predicate":{"tier":"full","observed_at":"2026-01-01T00:00:00Z",
        "observed":{"runner":"wrapper","checks":{"check":{"exit_code":0,"command":["true"]}}}}});
    for (pointer, bad) in [
        ("/predicate/observed/checks", json!([])),
        ("/predicate/observed/checks/check/exit_code", json!(false)),
        ("/predicate/observed/checks/check/command", json!([1])),
        ("/predicate/observed/inputs", json!({"x":1})),
        ("/predicate/observed/inputs", json!([])),
        ("/predicate/observed_at", json!("naive")),
        ("/predicate/tier", Value::Null),
        ("/predicate/observed/runner", Value::Null),
    ] {
        let mut value = base.clone();
        if pointer.ends_with("/inputs") {
            value["predicate"]["observed"]["inputs"] = bad;
        } else {
            *value.pointer_mut(pointer).unwrap() = bad;
        }
        let doc = Document::from_bytes(value.to_string().as_bytes()).unwrap();
        assert!(
            DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], "agent/alice").is_none(),
            "{pointer}"
        );
    }
}

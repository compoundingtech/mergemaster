use super::*;
use crate::evidence::{
    legacy_output,
    legacy_policy::normalized_text::NormalizedText,
    legacy_verify::{
        Failure,
        require_all::{Lane, Record},
    },
};
use serde_json::Value;

#[test]
fn require_all_json_matches_pinned_aggregation_and_error_envelopes() {
    let fixtures = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/judgment-core/require-all-json/stdout.bin"
    ));
    assert_eq!(fixtures["cases"].as_array().unwrap().len(), 324);
    for observation in fixtures["cases"].as_array().unwrap() {
        let fixture = crate::oracle_digest::json(&observation["input"]);
        let value = &fixture["value"];
        let all = All {
            tree: value["tree"].as_str().unwrap(),
            satisfied: value["satisfied"].as_bool().unwrap(),
            decision: parse_decision(&value["decision"]),
            lanes: value["lanes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let item = &row[1];
                    let outcome = if item["satisfied"].as_bool().unwrap() {
                        Ok(Record {
                            record: item["record"].as_str().unwrap().into(),
                            signer: item["signer"].as_str().unwrap().into(),
                            tier: serde_json::from_value(item["tier"].clone()).unwrap(),
                        })
                    } else {
                        Err(Failure {
                            reason: match item["reason"].as_str().unwrap() {
                                "no_lane" => "no_lane",
                                "wrong_check" => "wrong_check",
                                _ => panic!("fixture reason"),
                            },
                            detail: NormalizedText::Codepoints(
                                serde_json::from_value(item["detail"].clone()).unwrap(),
                            ),
                            attempts: None,
                            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                        })
                    };
                    (
                        serde_json::from_value(row[0].clone()).unwrap(),
                        Lane {
                            require: match item["require"].as_str().unwrap() {
                                "shadow" => RequireMode::Shadow,
                                "reject" => RequireMode::Reject,
                                _ => panic!("off lane escaped"),
                            },
                            outcome,
                            decision: parse_decision(&item["decision"]),
                        },
                    )
                })
                .collect(),
        };
        let mut actual = String::new();
        legacy_output::write(&mut actual, |w| all.write_json(w)).unwrap();
        crate::oracle_digest::assert_value(&Value::String(actual), &observation["wire"]);
    }
    assert_eq!(fixtures["errors"].as_array().unwrap().len(), 3);
    for observation in fixtures["errors"].as_array().unwrap() {
        let fixture = crate::oracle_digest::json(&observation["input"]);
        let error = PolicyError {
            resource: None,
            origin: if fixture["exception"] == true {
                crate::evidence::legacy_policy::ErrorOrigin::Exception {
                    class: "OverflowError",
                }
            } else {
                crate::evidence::legacy_policy::ErrorOrigin::Failure
            },
            reason: if fixture["value"]["reason"] == "no_policy" {
                "no_policy"
            } else {
                "error"
            },
            detail: NormalizedText::Codepoints(
                serde_json::from_value(fixture["source_detail"].clone()).unwrap(),
            ),
        };
        let mut actual = String::new();
        legacy_output::write(&mut actual, |w| write_error(&error, w)).unwrap();
        crate::oracle_digest::assert_value(&Value::String(actual), &observation["wire"]);
    }
}
fn parse_decision(value: &Value) -> Decision {
    match value.as_str().unwrap() {
        "ok" => Decision::Ok,
        "reject" => Decision::Reject,
        "would-reject" => Decision::WouldReject,
        _ => panic!("fixture decision"),
    }
}

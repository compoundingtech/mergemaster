use crate::evidence::{
    legacy_output,
    legacy_policy::{ErrorOrigin, PolicyDocument},
    legacy_verify::failure_json::WireError,
};
use serde_json::Value;
#[test]
fn outer_kind_diagnostics_match_pinned_handlers_losslessly() {
    let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/policy-kind-level/outer-kind-diagnostics/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.len(), 174);
    let mut exceptions = 0;
    for case in cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let error = PolicyDocument::parse(case["text"].as_str().unwrap(), name.as_slice())
            .unwrap()
            .into_rules("org/repo")
            .unwrap_err();
        let origin = if case["exception"].is_null() {
            ErrorOrigin::Failure
        } else {
            assert_eq!(case["exception"], "AttributeError");
            exceptions += 1;
            ErrorOrigin::Exception {
                class: "AttributeError",
            }
        };
        assert_eq!(error.origin, origin);
        assert_eq!(error.reason, case["reason"]);
        assert_eq!(
            serde_json::json!(error.detail.borrowed().points().collect::<Vec<_>>()),
            case["detail"]
        );
        let view = WireError::from_policy(&error);
        let mut single = String::new();
        legacy_output::write(&mut single, |w| view.write_json(name.as_slice().into(), w)).unwrap();
        assert_eq!(single, case["single"]);
        let mut global = String::new();
        legacy_output::write(&mut global, |w| view.write_global(w)).unwrap();
        assert_eq!(global, case["global_"]);
    }
    assert_eq!(exceptions, 54);
}

#[test]
fn integer_and_float_zero_overrides_stay_falsy_like_python() {
    use crate::evidence::legacy_verify::statement_document::{Document, Node};
    let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/policy-kind-level/zero-overrides/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let literal = case["literal"].as_str().unwrap();
        let document = Document::from_text_with_depth_limit(literal, None).unwrap();
        if case["integer"] == true {
            assert!(matches!(document.root(), Node::Integer(decimal) if decimal == "0"));
        } else {
            assert!(matches!(document.root(), Node::Float(number) if *number == 0.0));
            if literal == "-0.0" {
                assert!(
                    matches!(document.root(), Node::Float(number) if number.is_sign_negative())
                );
            }
        }
        let rules = PolicyDocument::parse(case["text"].as_str().unwrap(), "check")
            .unwrap()
            .into_rules("org/repo")
            .unwrap();
        assert!(rules.kinds[0].1.by_level.is_empty(), "{literal}");
    }
}

use crate::evidence::{
    legacy_output,
    legacy_policy::{ErrorOrigin, PolicyDocument},
    legacy_verify::failure_json::WireError,
};
use serde_json::Value;
#[test]
fn level_override_diagnostics_match_pinned_handlers_losslessly() {
    let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/policy-kind-level/level-diagnostics/stdout.bin"
    ))
    .unwrap();
    let failure_count = cases
        .iter()
        .filter(|case| case["exception"].is_null())
        .count();
    let exceptions = cases.len() - failure_count;
    for case in &cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let error = PolicyDocument::parse(case["text"].as_str().unwrap(), name.as_slice())
            .unwrap()
            .into_rules("org/repo")
            .unwrap_err();
        assert!(matches!(
            error.origin,
            ErrorOrigin::Failure
                | ErrorOrigin::Exception {
                    class: "KeyError" | "TypeError"
                }
        ));
        if case["exception"].is_string() {
            assert_eq!(case["exception"], "TypeError");
            let class = "TypeError";
            assert_eq!(error.origin, ErrorOrigin::Exception { class });
        } else {
            assert_eq!(error.origin, ErrorOrigin::Failure);
        }
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
    assert_eq!((cases.len(), failure_count, exceptions), (198, 192, 6));
}

#[test]
fn level_surrogate_and_wide_number_refusals_match_python() {
    let cases: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/oracle/policy-kind-level/level-surrogate-wide-numbers/stdout.bin"
    ))
    .unwrap();
    assert_eq!(cases.len(), 40);
    for case in cases {
        let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
        let error = PolicyDocument::parse(case["text"].as_str().unwrap(), check.as_slice())
            .unwrap()
            .into_rules("org/repo")
            .unwrap_err();
        assert_eq!(error.origin, ErrorOrigin::Failure);
        assert_eq!(error.reason, case["reason"]);
        assert_eq!(
            serde_json::json!(error.detail.borrowed().points().collect::<Vec<_>>()),
            case["detail"]
        );
    }
}

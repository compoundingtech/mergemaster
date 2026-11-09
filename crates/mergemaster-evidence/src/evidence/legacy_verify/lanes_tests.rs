use super::*;
use serde_json::json;
fn oracle(script: &str, cases: &str) -> Value {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
    let output = std::process::Command::new("python3")
        .args(["-c", script, &root, cases])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn lane_schema_matches_oracle_validation_order() {
    let mut docs = Vec::new();
    let base = json!({"argv":["run"],"definition_paths":["src","src"]});
    for field in ["tree_inputs", "absent_paths"] {
        for value in [
            json!(null),
            json!(false),
            json!(0),
            json!(0.0),
            json!(-0.0),
            json!(""),
            json!({}),
            json!([]),
            json!("src"),
            json!({"src":1}),
            json!(true),
            json!(1),
            json!(["src"]),
            json!(["."]),
            json!([null]),
        ] {
            let mut entry = base.clone();
            entry[field] = value;
            docs.push(json!({"version":1,"lanes":{"check":entry}}).to_string());
        }
    }
    for entry in [
        base.clone(),
        json!({}),
        json!({"argv":[],"definition_paths":["src"]}),
        json!({"argv":[["run"]],"definition_paths":["src"]}),
        json!({"argv":["run"],"definition_paths":["."]}),
        json!({"argv":["run"],"definition_paths":["src"],"unknown":1}),
        json!({"argv":["run"],"definition_paths":["src"],"ci_inputs":["ci.yml::jobs.test"]}),
        json!({"argv":["run"],"definition_paths":["src"],"ci_inputs":[]}),
    ] {
        docs.push(json!({"version":1,"lanes":{"check":entry}}).to_string());
    }
    for version in [json!(true), json!(1.0), json!(false), json!(2)] {
        docs.push(json!({"version":version,"lanes":{"check":base}}).to_string());
    }
    docs.extend(["{",r#"{"version":1,"lanes":{}}"#,r#"{"version":1,"lanes":{"unrelated":1e1000,"check":{"argv":["run"],"definition_paths":["src"]}}}"#,r#"{"version":1,"lanes":{"unrelated":1e1000}}"#].map(str::to_owned));
    let expected = oracle(
        r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for text in json.loads(sys.argv[2]):
    try:
        results.append(oracle['lane_rules'](text, 'check'))
    except oracle['Failure'] as failure:
        results.append(dict(reason=failure.reason))
    except TypeError:
        results.append(dict(reason='error', exception='TypeError'))
print(json.dumps(results))
"#,
        &json!(docs).to_string(),
    );
    assert_eq!(docs.len(), 46);
    assert_eq!(expected.as_array().unwrap().len(), docs.len());
    let mut crashes = 0;
    for (doc, mut expected) in docs
        .iter()
        .zip(expected.as_array().unwrap().iter().cloned())
    {
        if expected
            .as_object_mut()
            .unwrap()
            .remove("exception")
            .is_some()
        {
            crashes += 1;
        }
        let actual = LaneRules::parse(doc, "check")
            .map(|r| json!(r))
            .unwrap_or_else(|e| json!({"reason":e.reason}));
        assert_eq!(actual, expected, "{doc}");
    }
    assert_eq!(crashes, 10);
}

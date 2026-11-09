use super::*;
use serde_json::{Value as Json, json};
fn doc(value: &str) -> String {
    format!(r#"{{"version":1,"lanes":{{"check":{value}}}}}"#)
}
#[test]
fn guarded_entries_and_refusals_match_oracle_inventory() {
    let mut cases = vec![
        (
            [doc("1"), doc("1.0")],
            [None, Some("lane-entry-float-text")],
        ),
        ([doc(r#""\Infinity""#), doc("1Infinity")], [None, None]),
    ];
    for number in [
        "1e16",
        "1e-5",
        "0.1",
        "5e-324",
        "1.7976931348623157e308",
        "1e400",
        "-0.0",
        "0.0",
    ] {
        cases.push((
            [doc(number), doc(number)],
            [Some("lane-entry-float-text"); 2],
        ));
    }
    let valid = r#"{"argv":["run"],"definition_paths":["src"]}"#;
    let zero_input = doc(r#"{"argv":["run"],"definition_paths":["src"],"tree_inputs":0.0}"#);
    cases.push((
        [zero_input.clone(), zero_input],
        [Some("lane-entry-float-text"); 2],
    ));
    for other in ["NaN", "Infinity", "-Infinity", r#""\ud800""#] {
        let text = format!(r#"{{"version":1,"lanes":{{"check":{valid},"other":{other}}}}}"#);
        cases.push((
            [text.clone(), text],
            [Some("lane-entry-json-extensions"); 2],
        ));
        cases.push((
            [doc(other), doc(other)],
            [Some("lane-entry-json-extensions"); 2],
        ));
    }
    for digits in [4300, 4301] {
        let text = doc(&"9".repeat(digits));
        cases.push(([text.clone(), text], [None, None]));
    }
    for depth in [
        MAX_CONTAINERS - 1,
        MAX_CONTAINERS,
        MAX_CONTAINERS + 1,
        200,
        1200,
    ] {
        let n = depth - 2; // Root and lanes objects also count as open containers.
        let text = format!(
            r#"{{"version":1,"lanes":{{"check":{valid},"other":{}null{}}}}}"#,
            "[".repeat(n),
            "]".repeat(n)
        );
        let reason = (depth > MAX_CONTAINERS).then_some("lane-entry-nesting-depth");
        cases.push(([text.clone(), text], [reason; 2]));
    }
    let rust: Vec<_> = cases
        .iter()
        .map(|(texts, _)| {
            texts.each_ref().map(|t| {
                selected(t, "check")
                    .map(|v| json!({"present":v.is_some()}))
                    .unwrap_or_else(|e| json!({"reason":e.reason}))
            })
        })
        .collect();
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
    let fractal = std::env::var("MERGEMASTER_FRACTAL_FIXTURE")
        .expect("MERGEMASTER_FRACTAL_FIXTURE must point to the pinned Fractal consumer");
    let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
gate = runpy.run_path(sys.argv[2] + '/scripts/ci-evidence-gate')
results = []
for texts, rust in zip(json.loads(sys.argv[3]),json.loads(sys.argv[4])):
    sides = []
    for text, actual in zip(texts,rust):
        try:
            entry = dict(text=oracle['lane_entry'](text,'check'))
        except RecursionError:
            entry = dict(crash='RecursionError')
        try:
            schema = dict(rules=oracle['lane_rules'](text,'check'))
        except oracle['Failure'] as failure:
            schema = dict(reason=failure.reason)
        except (TypeError,RecursionError) as error:
            schema = dict(crash=type(error).__name__)
        category = gate['classify'](1,dict(satisfied=False,reason=actual['reason'])) if 'reason' in actual else None
        sides.append(dict(entry=entry,schema=schema,category=category))
    equal = None if any('crash' in side['entry'] for side in sides) else sides[0]['entry']['text'] == sides[1]['entry']['text']
    results.append(dict(sides=sides,equal=equal))
print(json.dumps(results))
"#;
    let texts: Vec<_> = cases.iter().map(|c| &c.0).collect();
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            script,
            &root,
            &fractal,
            &json!(texts).to_string(),
            &json!(rust).to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let oracle: Vec<Json> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(oracle.len(), cases.len());
    for (((texts, reasons), actual), expected) in cases.iter().zip(&rust).zip(&oracle) {
        println!("{}", json!({"oracle":expected,"rust":actual}));
        for i in 0..2 {
            if let Some(reason) = reasons[i] {
                assert_eq!(actual[i]["reason"], reason);
                assert_eq!(expected["sides"][i]["category"], "rejected");
            } else {
                assert_eq!(
                    actual[i]["present"],
                    !expected["sides"][i]["entry"]["text"].is_null(),
                    "{}",
                    texts[i]
                );
            }
        }
    }
    // The pinned Python accepts 1200 containers, just as it accepts the 200-container row.
    for i in 0..2 {
        let deep = &oracle.last().unwrap()["sides"][i];
        let reference = &oracle[oracle.len() - 2]["sides"][i];
        assert!(deep["entry"]["text"].is_string() && deep["schema"]["rules"].is_object());
        assert_eq!(deep["entry"], reference["entry"]);
        assert_eq!(deep["schema"], reference["schema"]);
    }
}

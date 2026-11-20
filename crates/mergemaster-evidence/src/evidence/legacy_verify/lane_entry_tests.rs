use super::*;
use serde_json::{Value as Json, json};
fn doc(value: &str) -> String {
    format!(r#"{{"version":1,"lanes":{{"check":{value}}}}}"#)
}
#[test]
fn canonical_text_and_conservative_refusals_match_oracle_inventory() {
    let mut cases = vec![
        (
            [doc("1"), doc("1.0")],
            [None, Some("lane-entry-float-text")],
        ),
        ([doc("true"), doc("1")], [None, None]),
        (
            [
                doc(r#"{"b":[[],{"é":"😀"}],"a":null}"#),
                doc(r#"{"a":null,"b":[[],{"é":"😀"}]}"#),
            ],
            [None, None],
        ),
        ([doc("-0"), doc("0")], [None, None]),
        (
            [
                doc("100000000000000000000000"),
                doc("100000000000000000000000"),
            ],
            [None, None],
        ),
        (
            [
                r#"{"lanes":{"check":false,"check":{"z":2,"a":1}}}"#.into(),
                doc(r#"{"a":1,"z":2}"#),
            ],
            [None, None],
        ),
        ([doc(r#""\Infinity""#), doc("1Infinity")], [None, None]),
        (["{}".into(), doc("null")], [None, None]),
        ([doc("[]"), doc("{}")], [None, None]),
        (
            [
                doc(r#""\"\\\n\r\t\u0000\u007fé😀""#),
                doc(r#""\"\\\n\r\t\u0000\u007f\u00e9\ud83d\ude00""#),
            ],
            [None, None],
        ),
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
    // Compare raw declarations, not schema-normalized order, duplicates or omitted fields.
    for (left, right) in [
        (
            r#"{"argv":["run"],"definition_paths":["src","tools"]}"#,
            r#"{"argv":["run"],"definition_paths":["tools","src"]}"#,
        ),
        (
            r#"{"argv":["run"],"definition_paths":["src","src"]}"#,
            valid,
        ),
        (
            valid,
            r#"{"argv":["run"],"definition_paths":["src"],"absent_paths":[]}"#,
        ),
    ] {
        cases.push(([doc(left), doc(right)], [None, None]));
    }
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
                canonical(t, "check")
                    .map(|v| json!({"text":v}))
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
    let output = crate::pinned_python::command()
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
        let first = &texts[0];
        let id = if first == &doc("1") && texts[1] == doc("1.0") {
            Some(("lane-float-1.0", 1))
        } else if first == &doc("-0.0") {
            Some(("lane-float-negative-zero", 0))
        } else if first == &doc("1e400") {
            Some(("lane-float-overflow", 0))
        } else if first.contains(r#""other":NaN"#) {
            Some(("lane-nan", 0))
        } else if first.contains(r#""other":Infinity"#) {
            Some(("lane-positive-infinity", 0))
        } else if first.contains(r#""other":-Infinity"#) {
            Some(("lane-negative-infinity", 0))
        } else if first.contains(r#""other":"\ud800""#) {
            Some(("lane-lone-surrogate", 0))
        } else {
            match first.matches('[').count() {
                // The valid entry contributes argv and definition_paths arrays.
                128 => Some(("lane-depth-128", 0)),
                200 => Some(("lane-depth-200", 0)),
                1200 => Some(("lane-depth-1200", 0)),
                _ => None,
            }
        };
        if let Some((id, side)) = id {
            crate::evidence::legacy_verify::divergence_witnesses::capture(
                id,
                json!({"text":texts[side],"lane":"check"}),
                expected["sides"][side]["entry"].clone(),
                actual[side].clone(),
            );
        }
        for i in 0..2 {
            if let Some(reason) = reasons[i] {
                assert_eq!(actual[i]["reason"], reason);
                assert_eq!(expected["sides"][i]["category"], "rejected");
            } else {
                assert_eq!(actual[i], expected["sides"][i]["entry"], "{}", texts[i]);
            }
        }
        if reasons == &[None, None] {
            assert_eq!(
                actual[0]["text"] == actual[1]["text"],
                expected["equal"].as_bool().unwrap()
            );
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

#[test]
fn lane_optional_and_shadowed_witnesses_execute_both_schemas() {
    use crate::evidence::legacy_verify::lanes::LaneRules;
    let valid = r#"{"argv":["run"],"definition_paths":["src"]}"#;
    let mut cases = Vec::new();
    for (id, token) in [
        ("lane-null", "null"),
        ("lane-false", "false"),
        ("lane-int-zero", "0"),
        ("lane-float-zero", "0.0"),
        ("lane-negative-float-zero", "-0.0"),
    ] {
        cases.push((
            id,
            doc(&format!(
                r#"{{"argv":["run"],"definition_paths":["src"],"tree_inputs":{token}}}"#
            )),
        ));
    }
    cases.push((
        "shadowed-invalid-lanes",
        format!(r#"{{"version":1,"lanes":1e400,"lanes":{{"check":{valid}}}}}"#),
    ));
    cases.push((
        "shadowed-invalid-selected-lane",
        format!(r#"{{"version":1,"lanes":{{"check":1e400,"check":{valid}}}}}"#),
    ));
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let output = crate::pinned_python::command()
        .args(["-c", r#"
import json,runpy,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
results=[]
for _,text in json.loads(sys.argv[2]):
 try: result={'rules':o['lane_rules'](text,'check')}
 except o['Failure'] as e: result={'reason':e.reason,'detail':list(map(ord,e.detail)),'origin':'Failure'}
 except Exception as e: result={'origin':type(e).__name__,'detail':list(map(ord,str(e)))}
 results.append(result)
print(json.dumps(results))
"#, &root, &json!(cases).to_string()])
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let python: Vec<Json> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(python.len(), cases.len());
    for ((id, text), python) in cases.iter().zip(python) {
        let rust = LaneRules::parse(text, "check")
            .map(|rules| json!({"rules":rules}))
            .unwrap_or_else(|error| {
                json!({
                    "reason":error.reason,
                    "detail":error.detail.borrowed().points().collect::<Vec<_>>(),
                    "origin":format!("{:?}",error.origin),
                })
            });
        crate::evidence::legacy_verify::divergence_witnesses::capture(
            id,
            json!({"text":text,"lane":"check"}),
            python,
            rust,
        );
    }
}

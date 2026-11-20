use super::select_json;
use serde_json::{Value, json};
#[test]
fn lossless_selector_preserves_parse_before_lookup() {
    use crate::evidence::legacy_verify::{value_inputs::TextRef, workflow::workflow_job};
    let text = r#"{"é":{"😀":1},"":{"":2}}"#;
    for selector in ["é.😀", ".", "missing", "é.missing"] {
        let points: Vec<_> = selector.chars().map(u32::from).collect();
        assert_eq!(
            select_json(text, "fixture.json", TextRef::Points(&points)).unwrap(),
            select_json(text, "fixture.json", selector).unwrap()
        );
    }
    let surrogate = TextRef::Points(&[0xd800]);
    assert_eq!(select_json(text, "fixture.json", surrogate).unwrap(), None);
    for invalid in ["not JSON", r#"{"other":"\ud800"}"#, r#"{"other":NaN}"#] {
        let expected = select_json(invalid, "fixture.json", "missing").unwrap_err();
        let actual = select_json(invalid, "fixture.json", surrogate).unwrap_err();
        assert_eq!(actual.origin, expected.origin);
        assert_eq!(actual.reason, expected.reason);
        assert_eq!(actual.detail, expected.detail);
    }
    let workflow = "name: ci\njobs:\n  test:\n    runs-on: ubuntu-latest\n";
    assert_eq!(
        workflow_job(workflow, TextRef::Points(&[116, 101, 115, 116])).unwrap(),
        workflow_job(workflow, "test").unwrap()
    );
    assert_eq!(workflow_job(workflow, surrogate).unwrap(), None);
    let invalid = "jobs:\n    malformed\n";
    let expected = workflow_job(invalid, "missing").unwrap_err();
    let actual = workflow_job(invalid, surrogate).unwrap_err();
    assert_eq!(actual.origin, expected.origin);
    assert_eq!(actual.detail, expected.detail);
}
#[test]
fn selected_json_matches_oracle_or_explicit_rejected_reason() {
    type Case = (
        String,
        &'static str,
        Option<&'static str>,
        Option<(&'static str, usize)>,
    );
    let mut cases: Vec<Case> = [
        r#"{"selected":{"z":1,"a":[null,true,"é😀"]}}"#,
        r#"{"selected":18446744073709551616}"#,
        r#"{"selected":-0}"#,
        r#"{"selected":0,"selected":1}"#,
        r#"{"selected":{"z":0,"z":1}}"#,
        r#"{"selected":1.0,"selected":1}"#,
        r#"{"selected":"\\ud800"}"#,
        r#"{"selected":"\ud83d\ude00"}"#,
        r#"{"selected":1,"other":1e400}"#,
        "{}",
        "[]",
        "null",
        "not JSON",
        r#"{"selected":01}"#,
    ]
    .map(|text| (text.into(), "selected", None, None))
    .into();
    cases.push((
        r#"{"selected":{"inner":1}}"#.into(),
        "selected.inner",
        None,
        None,
    ));
    for number in [
        "1.0",
        "-0.0",
        "1e16",
        "1e-5",
        "0.1",
        "5e-324",
        "1.7976931348623157e308",
        "1e400",
        "{\"n\":1.0}",
    ] {
        cases.push((
            format!("{{\"selected\":{number}}}"),
            "selected",
            Some("input-selection-float-text"),
            None,
        ));
    }
    for (value, token) in [
        ("NaN", "NaN"),
        ("Infinity", "Infinity"),
        ("-Infinity", "-Infinity"),
        (r#""\ud800""#, r#"\ud800"#),
        (r#""\udcff""#, r#"\udcff"#),
    ] {
        for text in [
            format!("{{\"selected\":{value}}}"),
            format!("{{\"é\":0,\"selected\":{{\"ok\":1}},\"other\":{value}}}"),
        ] {
            let at = text.find(token).unwrap();
            cases.push((
                text,
                "selected",
                Some("input-selection-json-extensions"),
                Some((token, at)),
            ));
        }
    }
    for digits in [4300, 4301] {
        cases.push((
            format!("{{\"selected\":{}}}", "9".repeat(digits)),
            "selected",
            None,
            None,
        ));
    }
    for depth in [127, 128, 200, 1200] {
        for member in ["selected", "other"] {
            let text = format!(
                "{{\"{member}\":{}null{},\"ok\":1}}",
                "[".repeat(depth - 1),
                "]".repeat(depth - 1)
            );
            cases.push((
                text,
                if member == "selected" {
                    "selected"
                } else {
                    "ok"
                },
                (depth > 127).then_some("input-selection-nesting-depth"),
                None,
            ));
        }
    }
    let results: Vec<_> = cases
        .iter()
        .map(|(text, key, _, _)| select_json(text, "fixture.json", *key))
        .collect();
    let actual: Vec<_> = results
        .iter()
        .map(|result| match result {
            Ok(bytes) => json!({"hex":bytes.as_ref().map(hex::encode)}),
            Err(e) => json!({"reason":e.reason,"detail":e.detail.to_string(),"origin":"Failure"}),
        })
        .collect();
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
    let fractal = std::env::var("MERGEMASTER_FRACTAL_FIXTURE")
        .expect("MERGEMASTER_FRACTAL_FIXTURE must point to the pinned Fractal consumer");
    let script = r#"
import json, runpy, sys
o = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
gate = runpy.run_path(sys.argv[2] + '/scripts/ci-evidence-gate')
results = []
for (text, key, _, _), actual in zip(json.loads(sys.argv[3]),json.loads(sys.argv[4])):
    try:
        value = o['select_part'](text,'fixture.json',key)
        result = dict(hex=value.hex() if value is not None else None)
    except o['Failure'] as e:
        result = dict(reason=e.reason,detail=str(e),origin='Failure')
    category = gate['classify'](1,dict(satisfied=False,reason=actual['reason'])) if 'reason' in actual else None
    results.append(dict(oracle=result,category=category))
print(json.dumps(results))
"#;
    let output = crate::pinned_python::command()
        .args([
            "-c",
            script,
            &root,
            &fractal,
            &json!(cases).to_string(),
            &json!(actual).to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual.len(), expected.len());
    for (i, (_, _, reason, token)) in cases.iter().enumerate() {
        if let Some(id) = reason {
            // Select one stable representative for each grouped contract.
            let representative = match *id {
                "input-selection-float-text" => cases[i].0 == r#"{"selected":1.0}"#,
                "input-selection-json-extensions" => cases[i].0 == r#"{"selected":NaN}"#,
                "input-selection-nesting-depth" => {
                    cases[i].0.starts_with(r#"{"selected":"#)
                        && cases[i].0.matches('[').count() == 127
                }
                _ => false,
            };
            if representative {
                crate::evidence::legacy_verify::divergence_witnesses::capture(
                    id,
                    json!({"text":cases[i].0,"selector":cases[i].1,"path":"fixture.json"}),
                    expected[i]["oracle"].clone(),
                    actual[i].clone(),
                );
            }
        }
        println!("{}", json!({"rust":actual[i],"oracle":expected[i]}));
        if let Some(reason) = reason {
            assert_eq!(actual[i]["reason"], *reason);
            assert_eq!(expected[i]["category"], "rejected");
            assert!(expected[i]["oracle"]["hex"].is_string());
            let detail = match *reason {
                "input-selection-float-text" => {
                    "selected value contains a floating number".to_owned()
                }
                "input-selection-nesting-depth" => "JSON exceeds 127 open containers".to_owned(),
                "input-selection-json-extensions" => {
                    let (token, at) = token.unwrap();
                    format!("unsupported JSON token {token} at byte offset {at}")
                }
                other => panic!("unexpected divergence {other}"),
            };
            assert_eq!(
                actual[i],
                json!({"reason":reason,"detail":detail,"origin":"Failure"})
            );
        } else {
            assert_eq!(actual[i], expected[i]["oracle"], "{}", cases[i].0);
        }
        if let Some((token, at)) = token {
            assert_eq!(
                results[i].as_ref().unwrap_err().detail.to_string(),
                format!("unsupported JSON token {token} at byte offset {at}")
            );
        }
    }
}

#[test]
fn policy_divergence_witnesses_execute_both_parsers() {
    use crate::evidence::legacy_policy::PolicyDocument;
    let entry = r#"{"trust_levels":["agent"],"kinds":{"wrapper":{"command":["true"]}}}"#;
    let checks = format!(r#"{{"check":{entry}}}"#);
    let cases = [
        (
            "max-age-above-u64",
            format!(r#"{{"version":1,"checks":{checks}}}"#).replacen(
                r#""trust_levels":"#,
                r#""max_age_s":18446744073709551616,"trust_levels":"#,
                1,
            ),
        ),
        (
            "shadowed-invalid-version",
            format!(r#"{{"version":1e400,"version":1,"checks":{checks}}}"#),
        ),
        (
            "shadowed-invalid-checks",
            format!(r#"{{"version":1,"checks":1e400,"checks":{checks}}}"#),
        ),
        (
            "shadowed-invalid-selected-check",
            format!(r#"{{"version":1,"checks":{{"check":1e400,"check":{entry}}}}}"#),
        ),
    ];
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let output = crate::pinned_python::command()
        .args(["-c", r#"
import json,runpy,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
results=[]
for id,text in json.loads(sys.argv[2]):
 try:
  rules=o['policy_rules'](text,'check','owner/repo')
  result={'max_age_s_decimal':str(rules['max_age_s'])} if id=='max-age-above-u64' else {'rules':rules}
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
    let python: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(python.len(), cases.len());
    for ((id, text), python) in cases.iter().zip(python) {
        let rust = PolicyDocument::parse(text, "check")
            .and_then(|document| document.into_rules("owner/repo"))
            .map(|rules| {
                if *id == "max-age-above-u64" {
                    let seconds = rules.header.max_age_s.as_ref().unwrap();
                    let mut decimal = String::new();
                    crate::evidence::legacy_output::write(&mut decimal, |writer| {
                        writer.policy_seconds(seconds)
                    })
                    .unwrap();
                    json!({"max_age_s_decimal":decimal})
                } else {
                    json!({"rules":rules})
                }
            })
            .unwrap_or_else(|error| {
                json!({
                    "reason":error.reason,
                    "detail":error.detail.borrowed().points().collect::<Vec<_>>(),
                    "origin":format!("{:?}",error.origin),
                })
            });
        crate::evidence::legacy_verify::divergence_witnesses::capture(
            id,
            json!({"text":text,"check":"check","repository":"owner/repo"}),
            python,
            rust,
        );
    }
}

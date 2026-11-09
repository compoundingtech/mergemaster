use super::select_json;
use serde_json::{Value, json};
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
        .map(|(text, key, _, _)| select_json(text, key))
        .collect();
    let actual: Vec<_> = results
        .iter()
        .map(|result| match result {
            Ok(bytes) => json!({"hex":bytes.as_ref().map(hex::encode)}),
            Err(e) => json!({"reason":e.reason}),
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
        result = dict(reason=e.reason)
    category = gate['classify'](1,dict(satisfied=False,reason=actual['reason'])) if 'reason' in actual else None
    results.append(dict(oracle=result,category=category))
print(json.dumps(results))
"#;
    let output = std::process::Command::new("python3")
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
        println!("{}", json!({"rust":actual[i],"oracle":expected[i]}));
        if let Some(reason) = reason {
            assert_eq!(actual[i]["reason"], *reason);
            assert_eq!(expected[i]["category"], "rejected");
            assert!(expected[i]["oracle"]["hex"].is_string());
        } else {
            assert_eq!(actual[i], expected[i]["oracle"], "{}", cases[i].0);
        }
        if let Some((token, at)) = token {
            assert_eq!(
                results[i].as_ref().unwrap_err().detail,
                format!("unsupported JSON token {token} at byte offset {at}")
            );
        }
    }
}

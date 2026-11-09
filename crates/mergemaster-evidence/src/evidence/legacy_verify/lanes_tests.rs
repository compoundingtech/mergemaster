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
#[test]
fn definition_preimages_and_hashes_match_oracle_bytes() {
    let cases = json!([
        {"entries":[],"argv":["run"],"absent":[]},
        {"entries":[{"mode":"100755","oid":"a","path":[122]},{"mode":"100644","oid":"b","path":[97]}],"argv":["", "\"\\\n\r\t\u{0008}\u{000c}\u{0000}\u{007f}","é中文😀"],"absent":["z","a"]},
        {"entries":[{"mode":"100644","oid":"c","path":[255]},{"mode":"100644","oid":"d","path":[240,159,152,128]},{"mode":"120000","oid":"e","path":[194]},{"mode":"100644","oid":"f","path":[195,169]}],"argv":["run"],"absent":[]}
    ]);
    let expected = oracle(
        r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for case in json.loads(sys.argv[2]):
    entries = [(e['mode'],e['oid'],bytes(e['path']).decode('utf-8','surrogateescape')) for e in case['entries']]
    argv, absent = case['argv'], case['absent']
    text = ''.join(f'{mode} {oid} {name}\n' for mode,oid,name in sorted(entries,key=lambda e:e[2])) + 'argv:' + json.dumps(argv)
    if absent:
        text += '\nabsent:' + json.dumps(sorted(absent))
    results.append(dict(bytes=text.encode('utf-8','surrogateescape').hex(),sha256=oracle['definition_digest'](entries,argv,absent)))
print(json.dumps(results))
"#,
        &cases.to_string(),
    );
    for (case, expected) in cases
        .as_array()
        .unwrap()
        .iter()
        .zip(expected.as_array().unwrap())
    {
        let mut entries: Vec<DefinitionEntry> =
            serde_json::from_value(case["entries"].clone()).unwrap();
        let argv: Vec<String> = serde_json::from_value(case["argv"].clone()).unwrap();
        let mut absent: Vec<String> = serde_json::from_value(case["absent"].clone()).unwrap();
        let mut bytes = Vec::new();
        definition_bytes(&mut entries, &argv, &mut absent, |part| {
            bytes.extend_from_slice(part)
        });
        assert_eq!(hex::encode(bytes), expected["bytes"]);
        assert_eq!(
            definition_digest(&mut entries, &argv, &mut absent),
            expected["sha256"]
        );
    }
}

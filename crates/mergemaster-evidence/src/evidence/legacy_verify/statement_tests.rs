use super::*;
use serde_json::{Value as Json, json};
#[test]
fn legacy_statement_shapes_match_oracle() {
    let tree = "a".repeat(40);
    let valid = json!({"_type":"https://in-toto.io/Statement/v1","predicateType":"https://compounding.tech/fractal/evidence/gate/v1",
        "subject":[{"name":"b".repeat(40),"digest":{"gitTree":tree}}],"predicate":{"schema_version":1,"change_id":"change","tier":"full","signer":null,
        "observed_at":"2026-01-01T12:30:00Z","observed":{"kind":"tests","runner":"wrapper","inputs":{},"checks":{"check":{"command":[""],"exit_code":0,"output_sha256":"c".repeat(64)}}}}});
    let mut cases = vec![valid.to_string(), "null".into(), "{}".into(), "[".into()];
    let mut absent_inputs = valid.clone();
    absent_inputs["predicate"]["observed"]
        .as_object_mut()
        .unwrap()
        .remove("inputs");
    cases.push(absent_inputs.to_string());
    let mutations: Json = serde_json::from_str(r#"[
      ["/_type",["wrong",null]], ["/predicateType",["https://smalltalk.dev/evidence/gate/v1","wrong"]],
      ["/subject",[[],null]], ["/subject/0/name",["bad",null]],
      ["/subject/0/digest",[{"gitTree":"wrong"},{"gitTree":"a","other":"x"}]],
      ["/predicate/schema_version",[true,1.0,false,2]], ["/predicate/change_id",[" \u001c","\u0085"," x ",null]],
      ["/predicate/tier",["degraded","test","other"]], ["/predicate/signer",["",1]],
      ["/predicate/observed/kind",["other",null]], ["/predicate/observed/runner",["",null]],
      ["/predicate/observed/inputs",[{}, {"a":" b "},{" ":"v"},{"k":false},null]],
      ["/predicate/observed/checks",[{}, {" ":{}},null]],
      ["/predicate/observed/checks/check/command",[[],[1],["","x"]]],
      ["/predicate/observed/checks/check/exit_code",[true,1.0,-5]],
      ["/predicate/observed/checks/check/output_sha256",["bad",null]]
    ]"#).unwrap();
    for mutation in mutations.as_array().unwrap() {
        for value in mutation[1].as_array().unwrap() {
            let mut v = valid.clone();
            *v.pointer_mut(mutation[0].as_str().unwrap()).unwrap() = value.clone();
            cases.push(v.to_string());
        }
    }
    for time in concat!(
        "2026-01-01|2026-01-01T12:30:00|20260101T1230Z|2026-W01-1T12Z|2026W011T12Z|2026-W01T12Z|2026W01T12Z|",
        "2026-01-01🐍12:30:00,123456789+013045.25|2026-01-01Z12Z|2026-01-01T12.5-00|2026-01-01T24Z|2026-01-01T24:00Z|",
        "2026-1-1T12:00Z|2026-W1T12Z|26-01-01T12Z|2026- 1-01T12Z|2026-02-30T12Z|0000-01-01T12Z|",
        "2026-01-01T12+24:00|2026-01-01T12+00:99|2026-01-01T12+23:59:59.99|2026-01-01T12+|2026-01-01T1Z|",
        "2026-01-01T1230.5Z|2026-01-01T12:30.5Z|2026-01-01T12+01.5|2026-01-01T12+0130.5|2026-01-01T12+01:30.5|",
        "2026-01-01T12+013045.5|2026-01-01T12+01:30:45.5|2026-01-01T12+00:00:99|2026-01-01T12+23:59:60|",
        "2026-01-01T24:00:00.0000001Z|2026-01-01T24:00:00.1Z|2026-01-01T24:00:01Z|2026-01-01T24:01Z|9999-12-31T24Z"
    ).split('|') {
        let mut v = valid.clone();
        v["predicate"]["observed_at"] = json!(time);
        cases.push(v.to_string());
    }
    for field in [
        "schema_version",
        "change_id",
        "tier",
        "signer",
        "observed_at",
        "observed",
    ] {
        let mut v = valid.clone();
        v["predicate"].as_object_mut().unwrap().remove(field);
        cases.push(v.to_string());
    }
    for n in [
        "-0".to_owned(),
        "9".repeat(100),
        "9".repeat(4300),
        "9".repeat(4301),
    ] {
        cases.push(
            valid
                .to_string()
                .replace("\"exit_code\":0", &format!("\"exit_code\":{n}")),
        );
    }
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned Python oracle required");
    let output=std::process::Command::new("python3").args(["-c",r#"
import json,runpy,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
print(json.dumps([o['statement_of'](s.encode(),sys.argv[2]) is not None for s in json.loads(sys.argv[3])]))
"#,&root,&tree,&json!(cases).to_string()]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<bool> = serde_json::from_slice(&output.stdout).unwrap();
    for (case, expected) in cases.iter().zip(expected) {
        assert_eq!(
            statement_of(case.as_bytes(), &tree).unwrap().is_some(),
            expected,
            "{case}"
        );
    }
    let parsed = statement_of(valid.to_string().as_bytes(), &tree)
        .unwrap()
        .unwrap();
    let at = |v, key| field(&parsed, v, key).unwrap();
    let predicate = at(parsed.root(), "predicate");
    assert!(text(at(predicate, "change_id"), "change"));
    let check = at(at(at(predicate, "observed"), "checks"), "check");
    assert!(text(
        parsed.node(array(at(check, "command")).unwrap()[0]),
        ""
    ));
    let mut bounded = valid.to_string().into_bytes();
    bounded.resize(MAX_STATEMENT_BYTES, b' ');
    assert!(statement_of(&bounded, &tree).unwrap().is_some());
    bounded.push(b' ');
    assert_eq!(
        statement_of(&bounded, &tree).unwrap_err().reason,
        "statement-too-large"
    );
    let zero = super::super::statement_document::Document::from_bytes(b"-0").unwrap();
    assert!(matches!(zero.root(), Node::Integer(n) if n == "0"));
}

#[test]
fn zoned_instants_match_python_without_narrowing_statement_times() {
    let script = r#"
import datetime,json,runpy,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
cases=['0001-01-01T00:00:00+23:59:59.999999',
 '9999-12-31T23:59:59.999999-23:59:59.999999',
 '9999-12-30T24:00Z','9999-12-31T24:00Z',
 '1969-12-31T23:59:59.999999Z','1970-01-01T00:00:00Z',
 '2026-01-01\ud80012:30Z','2026-01-01🌍12:30Z','2026-01-01Z12:30Z',
 '2026-01-01','2026-01-01T12:30','2026-W01','0000-01-01T00:00Z',
 '2026-01-01T24:00:00.000001Z','2026-01-01T24:00:00.0000009Z',
 '2026-01-01T12:30:00+00:00:00.000001',
 '2026-01-01T12:30:00-00:00:00.000001',
 '2026-01-01T12:30:00+00:00:00.999999','2026-01-01T12:30:00-00:00:00.999999']
for date in ['2026-01-01','20260101','2026-W01-4','2026W014','2026-W01','2026W01']:
 for clock in ['12','1230','12:30','123045','12:30:45','12:30:45.123456789','12:30:45,0000009','24:00']:
  for offset in ['Z','+01','-0130','+01:02:03.123456789','-00:00:00.000001','+00:60','+24:00']:
   cases.append(date+'T'+clock+offset)
out=[]
for text in cases:
 try:
  d=o['parse_time'](text); offset=d.utcoffset()
  if offset is None: result=None
  else:
   local=d.replace(tzinfo=None)-datetime.datetime(1970,1,1)
   result=((local.days*86400+local.seconds)*1000000+local.microseconds
           -(offset.days*86400+offset.seconds)*1000000-offset.microseconds)
 except (ValueError,OverflowError): result=None
 out.append(([ord(c) for c in text],result))
assert out[0][1]==-62135683199999999 and out[1][1]==253402387199999998
assert out[3][1] is None and out[4][1]==-1 and out[5][1]==0
assert out[6][1]==out[7][1] and out[14][1] is not None
print(json.dumps(out))
"#;
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let output = std::process::Command::new("python3")
        .args(["-c", script, &oracle])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<(Vec<u32>, Option<i64>)> = serde_json::from_slice(&output.stdout).unwrap();
    for (points, expected) in &cases {
        assert_eq!(zoned_time_micros(points), *expected, "{points:?}");
        assert_eq!(zoned_time(points), expected.is_some());
    }
    let instants: Vec<_> = cases
        .iter()
        .filter_map(|(points, expected)| Some((zoned_time_micros(points)?, (*expected)?)))
        .collect();
    for (actual_a, expected_a) in &instants {
        for (actual_b, expected_b) in &instants {
            assert_eq!(actual_a.cmp(actual_b), expected_a.cmp(expected_b));
        }
    }
}

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
            statement_of(case.as_bytes(), &tree).is_some(),
            expected,
            "{case}"
        );
    }
    let parsed = statement_of(valid.to_string().as_bytes(), &tree).unwrap();
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
    assert!(statement_of(&bounded, &tree).is_some());
    bounded.push(b' ');
    assert!(statement_of(&bounded, &tree).is_none());
    let zero = super::super::statement_document::Document::from_bytes(b"-0").unwrap();
    assert!(matches!(zero.root(), Node::Integer(n) if n == "0"));
}

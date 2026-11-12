use super::*;
use serde_json::{Value, json};

#[test]
fn selected_document_facts_match_the_oracle() {
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned Python oracle");
    let script = r#"
import copy, json, runpy, sys
from datetime import datetime, timezone
v = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
p = lambda s: list(map(ord, s))
base = {'_type':v['STATEMENT_TYPE'], 'predicateType':v['PREDICATE_TYPE'],
 'subject':[{'name':'b'*40,'digest':{'gitTree':'a'*40}}],
 'predicate':{'schema_version':1,'change_id':'change','tier':'full','signer':None,
 'observed_at':'2026-01-01T00:00:00Z','observed':{'kind':'tests','runner':'wrapper owner/repo',
 'checks':{'check':{'exit_code':0,'command':['true'],'output_sha256':'0'*64}}}}}
cases = []
def add(code=0, name='check', principal='agent/alice', time='2026-01-01T00:00:00Z', inputs=None, command=None, runner='wrapper owner/repo', tier='full', requested=None):
    doc = copy.deepcopy(base)
    predicate = doc['predicate']; observed = predicate['observed']
    predicate.update(observed_at=time, tier=tier); observed['runner'] = runner
    observed['checks'] = {name:{'exit_code':code,'command':command or ['true'],'output_sha256':'0'*64}}
    if inputs is not None: observed['inputs'] = inputs
    raw = json.dumps(doc); statement = v['statement_of'](raw, 'a'*40)
    assert statement is not None
    key = name if requested is None else requested
    expected = None
    if key in observed['checks']:
        result = observed['checks'][key]
        delta = v['parse_time'](time) - datetime(1970,1,1,tzinfo=timezone.utc)
        expected = dict(tier=p(tier),runner=p(runner),principal=principal,exit_code=str(code),
          observed_at=p(time),moment_micros=(delta.days*86400+delta.seconds)*1000000+delta.microseconds,
          failed=code != 0,level=principal.split('/',1)[0],command=list(map(p,result['command'])),
          inputs=None if inputs is None else [[p(k),p(x)] for k,x in inputs.items()])
    cases.append(dict(raw=raw,key=p(key),principal=principal,expected=expected))
for code in [0,-0,1,-1,2147483648,-2147483649,10**100,-10**100,10**4299]: add(code=code)
for name in ['x'*32,'x'*33,'x'*100,'🦀','\ud800','\ufffd','check\udfff']:
    add(name=name,inputs={'\ud800':'\udfff','\ufffd':'🦀'},command=['','\ud800','\ufffd','🦀'])
    add(name=name,requested='absent')
for time in ['1969-12-31T23:59:59.9999999+00:00','2026-W01-1T12+01:30',
             '20260101\ud800123456,1234567-00:00:30.25','2026-01-01T24:00+00:00']:
    add(time=time)
for principal in ['', 'host', '/alice', 'host/alice/extra']:
    add(principal=principal,inputs={})
for tier in ['full','test','degraded']: add(tier=tier,runner='wrapper\ud800 owner/repo')
print(json.dumps(cases))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script, &oracle])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 34);
    for case in cases {
        let doc = super::super::statement::statement_of(
            case["raw"].as_str().unwrap().as_bytes(),
            &"a".repeat(40),
        )
        .unwrap()
        .expect("oracle-valid statement");
        let key: Vec<u32> = serde_json::from_value(case["key"].clone()).unwrap();
        let actual = DocumentFacts::for_check(&doc, &key, case["principal"].as_str().unwrap()).map(|facts| {
            let inputs = facts.inputs.map(|node| {
                let Node::Object(entries) = node else { unreachable!() };
                entries.iter().map(|(key,id)| json!([key,string(doc.node(*id)).unwrap()])).collect::<Vec<_>>()
            });
            json!({"tier":facts.tier,"runner":facts.runner,"principal":facts.principal,
                "exit_code":facts.exit_code,"observed_at":facts.observed_at,"moment_micros":facts.moment_micros,
                "failed":facts.failed(),"level":facts.level(),"command":facts.command().collect::<Vec<_>>(),"inputs":inputs})
        });
        assert_eq!(actual.unwrap_or(Value::Null), case["expected"], "{case}");
    }
}

#[test]
fn document_facts_do_not_panic_on_ill_shaped_views() {
    let base = json!({"predicate":{"tier":"full","observed_at":"2026-01-01T00:00:00Z",
        "observed":{"runner":"wrapper","checks":{"check":{"exit_code":0,"command":["true"]}}}}});
    for (pointer, bad) in [
        ("/predicate/observed/checks", json!([])),
        ("/predicate/observed/checks/check/exit_code", json!(false)),
        ("/predicate/observed/checks/check/command", json!([1])),
        ("/predicate/observed/inputs", json!({"x":1})),
        ("/predicate/observed/inputs", json!([])),
        ("/predicate/observed_at", json!("naive")),
        ("/predicate/tier", Value::Null),
        ("/predicate/observed/runner", Value::Null),
    ] {
        let mut value = base.clone();
        if pointer.ends_with("/inputs") {
            value["predicate"]["observed"]["inputs"] = bad;
        } else {
            *value.pointer_mut(pointer).unwrap() = bad;
        }
        let doc = Document::from_bytes(value.to_string().as_bytes()).unwrap();
        assert!(
            DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], "agent/alice").is_none(),
            "{pointer}"
        );
    }
}

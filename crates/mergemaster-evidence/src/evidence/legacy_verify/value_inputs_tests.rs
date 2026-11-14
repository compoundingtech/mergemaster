use super::super::{statement_document::Document, value_checks_document};
use crate::evidence::legacy_policy::PolicyDocument;
use serde_json::{Value, json};
#[test]
fn document_value_guards_preserve_python_strings_and_lookup_keys() {
    let script = r#"
import json,runpy,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
def add(rule,inputs,run={}):
 try: o['value_checks'](rule,inputs,run,7); expected={'reason':'satisfied'}
 except o['Failure'] as e:
  expected={'reason':e.reason,'attempts':e.extra['attempts']}
  expected['detail']=list(map(ord,e.detail))
 except ValueError: expected={'reason':'ValueError'}
 policy=json.dumps(dict(version=1,checks={'check':dict(trust_levels=['agent'],kinds={'wrapper':dict(rule,command=['true'])})}))
 cases.append([policy,json.dumps(inputs),run,expected])
for value in ['strong','weak','\ud800','strong\ud800','🌍']:
 add({'input_order':{'x':['strong','weak']}},{'x':value,'unused\ud800':'\udfff'},{'x':'weak'})
for key in ['x','🌍'*32,'🌍'*33,'a'*100]:
 for value in ['same','same\ud800']:
  add({'base_inputs':{key:'.'}},{key:value},{key:'same'})
add({'input_order':{'🌍':['🌍','weak']}},{'🌍':'🌍'},{'🌍':'weak'})
add({'input_order':{'x':['�','weak']}},{'x':'\ud800'},{'x':'weak'})
add({'base_inputs':{'�':'.'}},{'\ud800':'same'},{'�':'same'})
for key in ['x','🦀']:
 add({'input_order':{key:['strong','weak']}},{},{})
 add({'input_order':{key:['strong','weak']}},{key:'weak'},{key:'strong'})
 add({'base_inputs':{key:'.'}},{},{})
 add({'base_inputs':{key:'.'}},{},{key:'same'})
for key in ['\ud800','🦀\udfff']:
 add({'input_order':{key:['strong','weak']}},{},{})
 add({'base_inputs':{key:'.'}},{},{})
add({'input_order':{'x':['\ud800','weak']}},{'x':'weak'},{})
shards={'shard_inputs':{'count':'n','results':'r','pull_request_count':2}}
for value in ['0=success','0=success\ud800','\ud800=success','0=success,1=success']:
 add(shards,{'n':'1','r':value})
for event in ['pull_request','pull_request\ud800','\ud800','merge_group']:
 add(shards,{'n':'1','r':'0=success','event_name':event})
add(shards,{'n':'\ud800','r':'0=success'})
for count in [None,'0','17','001','16']:
 add(shards,{} if count is None else {'n':count})
add({'shard_inputs':{'count':'\ud800','results':'\udfff'}},{})
print(json.dumps(cases))
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
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases {
        let rules = PolicyDocument::parse(case[0].as_str().unwrap(), "check")
            .unwrap()
            .into_rules("owner/repo")
            .unwrap();
        let document = Document::from_bytes(case[1].as_str().unwrap().as_bytes()).unwrap();
        let run = serde_json::from_value(case[2].clone()).unwrap();
        let actual = value_checks_document(&rules.kinds[0].1, &document, document.root(), &run, 7)
            .map(|()| json!({"reason":"satisfied"}))
            .unwrap_or_else(|e| {
                let mut result = json!({"reason":e.reason,"attempts":e.attempts});
                if case[3].get("detail").is_some() {
                    result["detail"] = json!(e.detail.borrowed().points().collect::<Vec<_>>());
                }
                result
            });
        if case[3]["reason"] == "ValueError" {
            // Existing unicode-shard-count divergence, not a new parser refusal.
            assert_eq!(actual, json!({"reason":"wrong_input","attempts":7}));
        } else {
            assert_eq!(actual, case[3], "{case}");
        }
    }
}

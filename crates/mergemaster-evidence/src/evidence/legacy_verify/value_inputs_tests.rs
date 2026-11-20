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
for count in ['١','１','𝟙','²','9'*4301]:
 add(shards,{'n':count,'r':'0=success'})
print(json.dumps(cases))
"#;
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let output = crate::pinned_python::command()
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
        let inputs = super::ValidatedInputs::new(&document, document.root()).unwrap();
        let actual = value_checks_document(&rules.kinds[0].1, inputs, &run, 7)
            .map(|()| json!({"reason":"satisfied"}))
            .unwrap_or_else(|e| {
                let mut result = json!({"reason":e.reason,"attempts":e.attempts});
                if case[3].get("detail").is_some() {
                    result["detail"] = json!(e.detail.borrowed().points().collect::<Vec<_>>());
                }
                result
            });
        // Witness selection must use the same lossless view: unrelated keys and
        // values deliberately contain lone surrogates that serde_json rejects.
        let count = super::InputMap::get_text(&inputs, "n".into());
        let id = match count {
            Some(value) if value.equals("١") => Some("shard-arabic-indic"),
            Some(value) if value.equals("１") => Some("shard-fullwidth"),
            Some(value) if value.equals("𝟙") => Some("shard-mathematical"),
            Some(value) if value.equals("²") => Some("shard-superscript-two"),
            Some(value) if value.len() == 4301 => Some("shard-ascii-over-4300"),
            _ => None,
        };
        if let Some(id) = id {
            crate::evidence::legacy_verify::divergence_witnesses::capture(
                id,
                json!({"policy":case[0],"inputs":case[1],"run_inputs":case[2],"attempts":7}),
                case[3].clone(),
                actual.clone(),
            );
        }
        if id.is_some() || case[3]["reason"] == "ValueError" {
            // Existing unicode-shard-count divergence, not a new parser refusal.
            assert_eq!(actual, json!({"reason":"wrong_input","attempts":7}));
        } else {
            assert_eq!(actual, case[3], "{case}");
        }
    }
}

#[test]
fn validated_views_refuse_wrong_shapes_and_foreign_ids() {
    use super::super::statement_document::Node;
    use super::{StringNodes, ValidatedInputs};
    for text in ["null", "[]", r#"{"x":false}"#, r#"{"x":["nested"]}"#] {
        let doc = Document::from_bytes(text.as_bytes()).unwrap();
        assert!(ValidatedInputs::new(&doc, doc.root()).is_none());
    }
    let doc = Document::from_bytes(br#"{"x":"value"}"#).unwrap();
    let invalid = Node::Object(indexmap::IndexMap::from([(vec![120], usize::MAX)]));
    assert!(ValidatedInputs::new(&doc, &invalid).is_none());
    let invalid = Node::Array(vec![usize::MAX]);
    assert!(StringNodes::new(&doc, &invalid).is_none());
    let doc = Document::from_bytes(br#"["a","\ud800"]"#).unwrap();
    let mut strings = StringNodes::new(&doc, doc.root()).unwrap();
    assert_eq!(strings.len(), 2);
    assert_eq!(strings.next(), Some(&[97][..]));
    assert_eq!(strings.len(), 1);
    assert_eq!(strings.next(), Some(&[0xd800][..]));
    assert_eq!(strings.len(), 0);
    assert_eq!(strings.next(), None);
}

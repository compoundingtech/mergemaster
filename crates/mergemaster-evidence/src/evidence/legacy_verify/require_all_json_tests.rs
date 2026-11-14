use super::*;
use crate::evidence::{
    legacy_output,
    legacy_policy::normalized_text::NormalizedText,
    legacy_verify::{
        Failure,
        require_all::{Lane, Record},
    },
};
use serde_json::Value;

#[test]
fn require_all_json_matches_pinned_aggregation_and_error_envelopes() {
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = std::process::Command::new("python3").args(["-c", r#"
import ast,itertools,json,runpy,sys
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path);cases=[]
ns=v['require_all'].__globals__
names=['😀','z','\ud800','a']
for modes in itertools.product(['off','shadow','reject'],repeat=4):
 for pattern in ['ok','failure','mixed','no-lane']:
  checks=dict(zip(names,modes))
  ns['policy_rules']=lambda text,check,repo:dict(require=checks[check])
  def lane(repo,tree,lane_file,check,lane_base):
   if pattern=='no-lane' and check=='\ud800': raise v['Failure']('no_lane','fixture lane missing\ud800')
  def verify(repo,tree,check,*args,**kwargs):
   if pattern=='failure' or pattern=='mixed' and check!='a': raise v['Failure']('wrong_check','fixture refusal\nquote" λ😀\udfff')
   return dict(record='record',signer='agent/fixture',tier='full')
  ns['lane_for']=lane;ns['verify']=verify
  result=v['require_all'](None,'a'*40,None,json.dumps(dict(version=1,checks=checks)),'fixture')
  wire=json.dumps(result,indent=2)
  result['lanes']=[[list(map(ord,k)),dict(item,tier=list(map(ord,item['tier']))) if item['satisfied'] else dict(item,detail=list(map(ord,item['detail'])))] for k,item in result['lanes'].items()]
  cases.append(dict(value=result,wire=wire))
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
errors=[]
for kind in ['Failure','Exception']:
 handler=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 dump=compile(ast.Expression(handler.body[0].body[0].value.args[0]),'<pinned-global-envelope>','eval')
 for reason in ['error','no_policy'] if kind=='Failure' else ['error']:
  env=dict(v,failure=v['Failure'](reason,'fixture detail\nλ😀\ud800'),error=OverflowError('fixture overflow\udfff'))
  wire=eval(dump,env);value=json.loads(wire);value['detail']=list(map(ord,value['detail']));errors.append(dict(value=value,wire=wire))
print(json.dumps(dict(cases=cases,errors=errors)))
"#, &oracle]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixtures: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fixtures["cases"].as_array().unwrap().len(), 324);
    for fixture in fixtures["cases"].as_array().unwrap() {
        let value = &fixture["value"];
        let all = All {
            tree: value["tree"].as_str().unwrap(),
            satisfied: value["satisfied"].as_bool().unwrap(),
            decision: parse_decision(&value["decision"]),
            lanes: value["lanes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let item = &row[1];
                    let outcome = if item["satisfied"].as_bool().unwrap() {
                        Ok(Record {
                            record: item["record"].as_str().unwrap().into(),
                            signer: item["signer"].as_str().unwrap().into(),
                            tier: serde_json::from_value(item["tier"].clone()).unwrap(),
                        })
                    } else {
                        Err(Failure {
                            reason: match item["reason"].as_str().unwrap() {
                                "no_lane" => "no_lane",
                                "wrong_check" => "wrong_check",
                                _ => panic!("fixture reason"),
                            },
                            detail: NormalizedText::Codepoints(
                                serde_json::from_value(item["detail"].clone()).unwrap(),
                            ),
                            attempts: None,
                            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                        })
                    };
                    (
                        serde_json::from_value(row[0].clone()).unwrap(),
                        Lane {
                            require: match item["require"].as_str().unwrap() {
                                "shadow" => RequireMode::Shadow,
                                "reject" => RequireMode::Reject,
                                _ => panic!("off lane escaped"),
                            },
                            outcome,
                            decision: parse_decision(&item["decision"]),
                        },
                    )
                })
                .collect(),
        };
        let mut actual = String::new();
        legacy_output::write(&mut actual, |w| all.write_json(w)).unwrap();
        assert_eq!(actual, fixture["wire"].as_str().unwrap());
    }
    assert_eq!(fixtures["errors"].as_array().unwrap().len(), 3);
    for fixture in fixtures["errors"].as_array().unwrap() {
        let error = PolicyError {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: if fixture["value"]["reason"] == "no_policy" {
                "no_policy"
            } else {
                "error"
            },
            detail: NormalizedText::Codepoints(
                serde_json::from_value(fixture["value"]["detail"].clone()).unwrap(),
            ),
        };
        let mut actual = String::new();
        legacy_output::write(&mut actual, |w| write_error(&error, w)).unwrap();
        assert_eq!(actual, fixture["wire"].as_str().unwrap());
    }
}
fn parse_decision(value: &Value) -> Decision {
    match value.as_str().unwrap() {
        "ok" => Decision::Ok,
        "reject" => Decision::Reject,
        "would-reject" => Decision::WouldReject,
        _ => panic!("fixture decision"),
    }
}

use super::*;
use crate::evidence::{
    legacy_output,
    legacy_policy::{ErrorOrigin, PolicyDocument},
    legacy_verify::failure_json::WireError,
};
#[test]
fn level_override_diagnostics_match_pinned_handlers_losslessly() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = std::process::Command::new("python3").args(["-c", r#"
import ast,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
def dump(kind,global_):
 h=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(h.body[0].body[0].value.args[0] if global_ else h.body[1].value.args[0]),'<handler>','eval')
cases=[]
base=dict(command=['run'],events=['pull_request'])
overrides=[None,{},dict(command=['run']),dict(base,unknown=True),dict(base,lane='base'),dict(base,lane=0)]
for events in [[],['push'],['pull_request','pull_request'],[[]],None]:
 overrides.append(dict(base,events=events) if events is not None else dict(command=['run']))
cases_by_override=[]
for value in overrides: cases_by_override.append(value)
for check in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 for level in ['agent','unlisted','']:
  for value in cases_by_override:
   text=json.dumps(dict(version=1,checks={check:dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['run'],by_level={level:value})))}))
   try: v['policy_rules'](text,check,'org/repo')
   except Exception as error:
    failure=isinstance(error,v['Failure']);kind='Failure' if failure else 'Exception'
    env=dict(v,failure=error,error=error,args=types.SimpleNamespace(check=check))
    cases.append(dict(text=text,name=list(map(ord,check)),exception=None if failure else type(error).__name__,reason=error.reason if failure else 'error',detail=list(map(ord,error.detail if failure else str(error))),single=eval(dump(kind,False),env),global_=eval(dump(kind,True),env)))
   else: raise AssertionError('expected refusal')
print(json.dumps(cases))
"#, &root]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let failure_count = cases
        .iter()
        .filter(|case| case["exception"].is_null())
        .count();
    let exceptions = cases.len() - failure_count;
    for case in &cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let error = PolicyDocument::parse(case["text"].as_str().unwrap(), name.as_slice())
            .unwrap()
            .into_rules("org/repo")
            .unwrap_err();
        assert!(matches!(
            error.origin,
            ErrorOrigin::Failure
                | ErrorOrigin::Exception {
                    class: "KeyError" | "TypeError"
                }
        ));
        if case["exception"].is_string() {
            assert!(matches!(
                case["exception"].as_str(),
                Some("KeyError") | Some("TypeError")
            ));
            let class = match case["exception"].as_str().unwrap() {
                "KeyError" => "KeyError",
                _ => "TypeError",
            };
            assert_eq!(error.origin, ErrorOrigin::Exception { class });
        } else {
            assert_eq!(error.origin, ErrorOrigin::Failure);
        }
        assert_eq!(error.reason, case["reason"]);
        assert_eq!(
            serde_json::json!(error.detail.borrowed().points().collect::<Vec<_>>()),
            case["detail"]
        );
        let view = WireError::from_policy(&error);
        let mut single = String::new();
        legacy_output::write(&mut single, |w| view.write_json(name.as_slice().into(), w)).unwrap();
        assert_eq!(single, case["single"]);
        let mut global = String::new();
        legacy_output::write(&mut global, |w| view.write_global(w)).unwrap();
        assert_eq!(global, case["global_"]);
    }
    assert_eq!(exceptions + failure_count, cases.len());
}

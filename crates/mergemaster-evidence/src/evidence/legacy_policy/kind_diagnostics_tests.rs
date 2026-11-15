use crate::evidence::{
    legacy_output,
    legacy_policy::{ErrorOrigin, PolicyDocument},
    legacy_verify::failure_json::WireError,
};
use serde_json::Value;
#[test]
fn outer_kind_diagnostics_match_pinned_handlers_losslessly() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = crate::pinned_python::command().args(["-c", r#"
import ast,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
def dump(kind,global_):
 h=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(h.body[0].body[0].value.args[0] if global_ else h.body[1].value.args[0]),'<handler>','eval')
cases=[]
for check in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 kinds=[{kind:dict(command=['run'])} for kind in ['unknown','😀','quote\'"\n','\u0378','\ud800','\udfff']]
 kinds += [dict(wrapper=value) for value in [None,{},dict(command=['run'],unknown=True),dict(command=[]),dict(command=['run'],trust_levels=[]),dict(command=['run'],trust_levels=['']),dict(command=['run'],runner_prefix=''),dict(command=['run'],runner_prefix=1)]]
 kinds += [dict(wrapper=dict(command=['run'],by_level=value)) for value in [True,1,1.5,'x',[1],2**64,10**100,1e400,-1e400]]
 for point in ['\ud800','\udfff']:
  kinds += [dict(wrapper=dict(command=['run'],**fields)) for fields in [
   dict(base_inputs={point:point}),dict(input_order={point:[point,point]}),dict(bind_inputs={point:None})]]
 for value in kinds:
  text=json.dumps(dict(version=1,checks={check:dict(trust_levels=['agent'],kinds=value)}))
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
    assert_eq!(cases.len(), 174);
    let mut exceptions = 0;
    for case in cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let error = PolicyDocument::parse(case["text"].as_str().unwrap(), name.as_slice())
            .unwrap()
            .into_rules("org/repo")
            .unwrap_err();
        let origin = if case["exception"].is_null() {
            ErrorOrigin::Failure
        } else {
            assert_eq!(case["exception"], "AttributeError");
            exceptions += 1;
            ErrorOrigin::Exception {
                class: "AttributeError",
            }
        };
        assert_eq!(error.origin, origin);
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
    assert_eq!(exceptions, 54);
}

#[test]
fn integer_and_float_zero_overrides_stay_falsy_like_python() {
    use crate::evidence::legacy_verify::statement_document::{Document, Node};
    let output = crate::pinned_python::command()
        .args([
            "-c",
            r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify');cases=[]
for literal in ['0','-0','0.0','-0.0','0e5']:
 entry=dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['run'],by_level='TOKEN')))
 text=json.dumps(dict(version=1,checks=dict(check=entry))).replace('"TOKEN"',literal)
 rules=v['policy_rules'](text,'check','org/repo')
 assert rules['kinds']['wrapper']['by_level']=={}
 value=json.loads(literal)
 cases.append(dict(literal=literal,text=text,integer=type(value) is int))
print(json.dumps(cases))
"#,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let literal = case["literal"].as_str().unwrap();
        let document = Document::from_text_with_depth_limit(literal, None).unwrap();
        if case["integer"] == true {
            assert!(matches!(document.root(), Node::Integer(decimal) if decimal == "0"));
        } else {
            assert!(matches!(document.root(), Node::Float(number) if *number == 0.0));
            if literal == "-0.0" {
                assert!(
                    matches!(document.root(), Node::Float(number) if number.is_sign_negative())
                );
            }
        }
        let rules = PolicyDocument::parse(case["text"].as_str().unwrap(), "check")
            .unwrap()
            .into_rules("org/repo")
            .unwrap();
        assert!(rules.kinds[0].1.by_level.is_empty(), "{literal}");
    }
}

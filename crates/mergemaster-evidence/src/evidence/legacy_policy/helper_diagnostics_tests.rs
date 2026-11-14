use super::*;
use crate::evidence::{legacy_output, legacy_verify::failure_json::WireError};
#[test]
fn rule_helper_diagnostics_match_pinned_handlers_losslessly() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = std::process::Command::new("python3").args(["-c", r#"
import ast,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
def dump(kind,global_):
 h=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(h.body[0].body[0].value.args[0] if global_ else h.body[1].value.args[0]),'<handler>','eval')
cases=[]
for name in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 for helper,rules in [('checked_command_inputs',[{},dict(command=[]),dict(command=[None]),dict(command=['run'],required_inputs=1),dict(command=['run'],bind_inputs={'x':1})]),('checked_base_inputs',[dict(base_inputs=[]),dict(base_inputs={'x':'../bad'}),dict(base_inputs={'x':'a\n'}),dict(base_inputs={'x':'x'*301})]),('checked_value_rules',[dict(input_order=[]),dict(input_order={'x':['a','a']}),dict(input_order={'x':[[],[]]}),dict(input_order={'x':[{},'a']}),dict(input_order={'':['a',[]]}),dict(input_order={'x':[[]]}),dict(shard_inputs=[]),dict(shard_inputs={'count':'n','results':'r','index':None})])]:
  for rule in rules:
   try: v[helper](rule.copy(),name)
   except Exception as error:
    failure=isinstance(error,v['Failure']);kind='Failure' if failure else 'Exception'
    env=dict(v,failure=error,error=error,args=types.SimpleNamespace(check=name))
    cases.append(dict(helper=helper,rule=rule,name=list(map(ord,name)),class_=None if failure else type(error).__name__,reason=error.reason if failure else 'error',detail=list(map(ord,error.detail if failure else str(error))),single=eval(dump(kind,False),env),global_=eval(dump(kind,True),env)))
   else: raise AssertionError('expected refusal')
print(json.dumps(cases))
"#, &root]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 102);
    let mut exceptions = 0;
    for case in cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let context = [TextRef::Points(&name)];
        let document = Document::from_bytes(case["rule"].to_string().as_bytes()).unwrap();
        let fields = Source::root(&document);
        let error = match case["helper"].as_str().unwrap() {
            "checked_command_inputs" => checked_command_inputs(fields, &context).unwrap_err(),
            "checked_base_inputs" => checked_base_inputs(fields, &context).unwrap_err(),
            "checked_value_rules" => {
                value_rules::checked_value_rules(fields, &context).unwrap_err()
            }
            _ => panic!("fixture helper"),
        };
        let origin = match case["class_"].as_str() {
            None => ErrorOrigin::Failure,
            Some("KeyError") => ErrorOrigin::Exception { class: "KeyError" },
            Some("TypeError") => ErrorOrigin::Exception { class: "TypeError" },
            _ => panic!("fixture exception"),
        };
        assert_eq!(error.origin, origin);
        exceptions += usize::from(origin != ErrorOrigin::Failure);
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
    assert_eq!(exceptions, 18);
    for text in [
        r#"{"version":1,"checks":{"x":{"trust_levels":["agent"],"kinds":{"wrapper":{}}}}}"#,
        r#"{"version":1,"checks":{"x":{"trust_levels":["agent"],"kinds":{"wrapper":{"command":["run"],"by_level":{"agent":{"events":["pull_request"]}}}}}}}"#,
    ] {
        let error = PolicyDocument::parse(text, "x")
            .unwrap()
            .into_rules("org/repo")
            .unwrap_err();
        assert_eq!(error.origin, ErrorOrigin::Failure);
    }
}

#[test]
fn declared_source_paths_preserve_nested_surrogate_diagnostics() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = std::process::Command::new("python3").args(["-c", r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
cases=[]
for point in ['\ud800','\udfff','😀','\u0378']:
 for item in [point,'!'+point,'x.json::'+point,point+'.yml::jobs.id']:
  for selectors in [False,True]:
   text=json.dumps([item])
   try: result=v['declared_paths'](json.loads(text),'fixture',selectors)
   except v['Failure'] as error:
    cases.append(dict(text=text,selectors=selectors,reason=error.reason,detail=list(map(ord,error.detail))))
   else: raise AssertionError('expected invalid literal')
print(json.dumps(cases))
"#, &root]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 32);
    for case in cases {
        let document = crate::evidence::legacy_verify::statement_document::Document::from_bytes(
            case["text"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let error = declared_source_paths(
            value_source::Source::root(&document),
            &[TextRef::Str("fixture")],
            case["selectors"].as_bool().unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.origin, ErrorOrigin::Failure);
        assert_eq!(error.reason, case["reason"]);
        assert_eq!(
            serde_json::json!(error.detail.borrowed().points().collect::<Vec<_>>()),
            case["detail"]
        );
    }
}

#[test]
fn full_policy_consumers_are_stack_safe_at_five_million_depth() {
    // Explicit divergence: Python's resource-dependent RecursionError around
    // depth 51.9k is not reproduced. Policy ingress keeps Rust's prior acceptance.
    for depth in [128, 129, 256, 257, 5_000_000] {
        let ignored = format!("{}0{}", "[".repeat(depth - 2), "]".repeat(depth - 2));
        let text = serde_json::json!({"version":1,"checks":{"ignored":"DEPTH",
        "check":{"trust_levels":["agent"],"inputs":["."],"kinds":{"wrapper":{
            "command":["run"],"required_inputs":["x"],"bind_inputs":{"x":"path"},
            "base_inputs":{"base":"path"},"input_order":{"rank":["a","b"]}
        }}}}})
        .to_string()
        .replacen("\"DEPTH\"", &ignored, 1);
        let names = check_names::sorted(&text).unwrap();
        assert_eq!(
            names,
            ["check", "ignored"].map(|s| s.chars().map(u32::from).collect::<Vec<_>>())
        );
        let header = PolicyDocument::parse(&text, "check")
            .unwrap()
            .into_header()
            .unwrap();
        assert_eq!(header.trust_levels, ["agent"]);
        let rules = PolicyDocument::parse(&text, "check")
            .unwrap()
            .into_rules("org/repo")
            .unwrap();
        assert_eq!(rules.kinds.len(), 1);
        assert_eq!(rules.kinds[0].1.inputs.command, ["run"]);
    }
}

#[test]
fn selected_payload_at_five_million_depth_is_stack_safe() {
    let template = serde_json::json!({"version":1,"checks":{"check":{
        "trust_levels":["agent"],"kinds":{"wrapper":{"command":"DEPTH"}}
    }}})
    .to_string();
    let shallow = template.replace("\"DEPTH\"", "[[0]]");
    let expected = PolicyDocument::parse(&shallow, "check")
        .unwrap()
        .into_rules("org/repo")
        .unwrap_err();
    let payload = format!("{}0{}", "[".repeat(5_000_000), "]".repeat(5_000_000));
    let text = template.replace("\"DEPTH\"", &payload);
    let document = Document::from_bytes_with_depth_limit(text.as_bytes(), None).unwrap();
    let selected = Source::root(&document)
        .get("checks")
        .unwrap()
        .get("check")
        .unwrap();
    let error = kind_rules::from_source(
        selected.get("kinds").unwrap(),
        &["agent".into()],
        "org/repo",
        "check".into(),
    )
    .unwrap_err();
    assert_eq!(error, expected);
    drop(document);
    let header = PolicyDocument::parse(&text, "check")
        .unwrap()
        .into_header()
        .unwrap();
    assert_eq!(header.trust_levels, ["agent"]);
    let error = PolicyDocument::parse(&text, "check")
        .unwrap()
        .into_rules("org/repo")
        .unwrap_err();
    assert_eq!(error, expected);
}

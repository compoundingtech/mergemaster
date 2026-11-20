use super::*;
use serde_json::{Value as Json, json};
fn wrap<T: serde::Serialize>(result: Result<T, PolicyError>) -> Json {
    match result {
        Ok(v) => json!({"value":v}),
        Err(e) => {
            json!({"error":e.detail.to_string(),"kind":match e.origin { ErrorOrigin::Exception{class}=>class,ErrorOrigin::Failure=>"Failure" }})
        }
    }
}
#[test]
fn operations_match_python_on_type_confused_fields() {
    let script = r#"
import importlib.machinery,importlib.util,json,posixpath,sys,tomllib
assert sys.version_info[:3]==(3,14,7)
l=importlib.machinery.SourceFileLoader('keys',sys.argv[1]); spec=importlib.util.spec_from_loader('keys',l); m=importlib.util.module_from_spec(spec); l.exec_module(m)
samples=['123','0','-0','0x0','0o0','0b0','true','false','1.5','-0.0','nan','1979-05-27','07:32:00','1979-05-27T07:32:00Z','[]','[1]','["*"]','{}','{x=1}','{"*"=1}',"''","'x'","'a/../b'",'{d={path="../lib"}}','{d={workspace=true}}']
cases=[]
for token in samples:
 raw='v='+token; v=tomllib.loads(raw)['v']
 for op in ['truthy','get','values','contains','norm','join','dependencies','inherited','spec']:
  try:
   if op=='truthy': result=bool(v)
   elif op=='get': (v or {}).get('x'); result=True
   elif op=='values': v.values(); result=True
   elif op=='contains': result='*' in v
   elif op=='norm': result=posixpath.normpath(v)
   elif op=='join': result=posixpath.normpath(posixpath.join('src/',v))
   elif op=='dependencies': result=m.dependency_paths(v,'src/',{})
   elif op=='inherited': result=m.dependency_paths({'d':{'workspace':True}},'src/',v)
   else: result=m.dependency_paths({'d':v},'src/',{})
   expected=dict(value=result)
  except Exception as e: expected=dict(error=str(e),kind=type(e).__name__)
  cases.append(dict(raw=raw,op=op,expected=expected))
print(json.dumps(cases))
"#;
    let oracle = crate::pinned_python::keys_oracle();
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .arg(oracle)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Vec<Json> = serde_json::from_slice(&out.stdout).unwrap();
    for case in &cases {
        let mut root = super::super::toml::parse(case["raw"].as_str().unwrap()).unwrap();
        let value = root.shift_remove("v").unwrap();
        let actual = match case["op"].as_str().unwrap() {
            "truthy" => wrap(Ok(truthy(&value))),
            "get" => wrap(object(Some(&value), true, "get").map(|_| true)),
            "values" => wrap(object(Some(&value), false, "values").map(|_| true)),
            "contains" => wrap(contains_star(&value)),
            "norm" => wrap(path(&value, None)),
            "join" => wrap(path(&value, Some("src/"))),
            "dependencies" => wrap(dependency_paths(Some(&value), "src/", None)),
            "inherited" => {
                let t = super::super::toml::parse("d={workspace=true}").unwrap();
                wrap(dependency_paths(
                    Some(&Value::Table(t)),
                    "src/",
                    Some(&value),
                ))
            }
            "spec" => {
                let mut t = Table::new();
                t.insert("d".into(), value);
                wrap(dependency_paths(Some(&Value::Table(t)), "src/", None))
            }
            _ => panic!("unknown operation"),
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 225);
}

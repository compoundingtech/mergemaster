use super::*;
use crate::evidence::legacy_policy::PolicyResource;
use serde_json::{Value, json};
fn outcome(result: Result<LaneRules, PolicyError>) -> Value {
    result.map(|r| json!({"ok":{"argv":r.argv.iter().map(|s| s.borrowed().points().collect::<Vec<_>>()).collect::<Vec<_>>(),"definition_paths":r.definition_paths,"tree_inputs":r.tree_inputs,"absent_paths":r.absent_paths,"ci_inputs":r.ci_inputs}}))
        .unwrap_or_else(|e| json!({"origin":match e.origin { ErrorOrigin::Failure => "Failure", ErrorOrigin::Exception { class } => class },"reason":e.reason,"detail":e.detail.borrowed().points().collect::<Vec<_>>()}))
}
#[test]
fn lane_parser_budgets_and_json_diagnostics_match_pinned_oracle() {
    let script = r#"
import json,os,pathlib,runpy,sys
sys.setrecursionlimit(10000)
v=runpy.run_path(str(pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify'))
base='{"version":1,"lanes":{"check":{"argv":["run"],"definition_paths":["src"]},"metadata":%s}}'
rows=[]
def add(text,resource=None):
 try:
  r=v['lane_rules'](text,'check');r['argv']=[list(map(ord,s)) for s in r['argv']];expected=dict(ok=r)
 except v['Failure'] as e:expected=dict(origin='Failure',reason=e.reason,detail=list(map(ord,str(e))))
 except Exception as e:expected=dict(origin=type(e).__name__,reason='error',detail=list(map(ord,str(e))))
 if resource is not None:assert 'ok' in expected
 rows.append(dict(text=text,resource=resource,expected=expected))
for extra in [0,1]:
 text=base%'0';add(text+' '*(1048576-len(text)+extra),'SourceBytes' if extra else None)
 text=base%json.dumps('é',ensure_ascii=False);add(text+' '*(1048576-len(text.encode())+extra),'SourceBytes' if extra else None)
 for kind in ['arrays','mixed']:
  depth=254+extra
  value='['*depth+'0'+']'*depth if kind=='arrays' else '['*(depth-1)+'{}'+']'*(depth-1)
  add(base%value,'ContainerDepth' if extra else None)
 for kind in ['scalars','empty','duplicates']:
  n=262144-(12 if kind=='duplicates' else 9)+extra
  value='['+','.join(['[]' if kind=='empty' else '0']*n)+']'
  if kind=='duplicates':value='{"x":0,"x":0,"a":'+value+'}'
  add(base%value,'Nodes' if extra else None)
for text in ['','{','\ufeff{}','[]','null','true','{"version":1,"lanes":[]}', '{"version":2,"lanes":{}}','{"version":true,"lanes":{}}','{"version":1.0,"lanes":{}}',base%'NaN',base%'Infinity',base%'1e309',base%('-'+'9'*4301),base%('9'*4300),base%'"\\ud800"',base%'{} trailing']:
 add(text)
for version in ['1','1.0','1e0','true','false','-0','null','"1"']:
 add((base%'0').replace('"version":1','"version":'+version))
print(json.dumps(rows))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 39);
    for row in rows {
        let result = LaneRules::parse(row["text"].as_str().unwrap(), TextRef::Str("check"));
        if let Some(resource) = row["resource"].as_str() {
            let resource = SourceResource::LaneJson(match resource {
                "SourceBytes" => PolicyResource::SourceBytes,
                "ContainerDepth" => PolicyResource::ContainerDepth,
                "Nodes" => PolicyResource::Nodes,
                _ => unreachable!(),
            });
            let error = result.err().unwrap();
            assert_eq!(error.resource, Some(resource.clone()));
            assert_eq!(error.detail, resource.detail());
            assert_eq!(error.origin, ErrorOrigin::Failure);
            assert_eq!(error.reason, "error");
        } else {
            assert_eq!(outcome(result), row["expected"]);
        }
    }
}

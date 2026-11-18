use super::*;
use serde_json::{Value, json};
#[test]
fn lossless_lane_schema_matches_exact_oracle_results() {
    let script = r#"
import json,os,pathlib,runpy
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])
v=runpy.run_path(str(p/'scripts/evidence-verify'));rows=[]
for name in ['check',chr(0xd800),'x\0'+chr(0xdcff)]:
 base=dict(argv=['run',chr(0xd800),'x\0y'],definition_paths=['src','src'])
 entries=[base,None,{},dict(base,argv=[]),dict(base,definition_paths=['.']),dict(base,extra=True),dict(base,ci_inputs=[])]
 for field in ['tree_inputs','absent_paths']:
  for value in [None,False,0,-0.0,'',{},[],True,1,'src',['.'],['../bad'],['src']]:entries.append(dict(base,**{field:value}))
 entries += [dict(base,tree_inputs=None,absent_paths=['.']),dict(base,tree_inputs=None,ci_inputs=[])]
 for entry in entries:
  text=json.dumps(dict(version=1,lanes={name:entry}))
  try: result=v['lane_rules'](text,name);result['argv']=[list(map(ord,s)) for s in result['argv']];expected=dict(ok=result)
  except v['Failure'] as e:expected=dict(origin='Failure',reason=e.reason,detail=list(map(ord,str(e))))
  except Exception as e:expected=dict(origin=type(e).__name__,reason='error',detail=list(map(ord,str(e))))
  rows.append(dict(text=text,name=list(map(ord,name)),expected=expected))
  for field in ['tree_inputs','absent_paths']:
   if isinstance(entry,dict) and type(entry.get(field)) is int and entry[field]==0:
    negative=text.replace('\"'+field+'\": 0','\"'+field+'\": -0')
    try:v['lane_rules'](negative,name);raise AssertionError('negative zero must refuse')
    except TypeError as e: negative_expected=dict(origin=type(e).__name__,reason='error',detail=list(map(ord,str(e))))
    rows.append(dict(text=negative,name=list(map(ord,name)),expected=negative_expected))
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
    assert_eq!(rows.len(), 111);
    for row in rows {
        let name: Vec<u32> = serde_json::from_value(row["name"].clone()).unwrap();
        let actual = LaneRules::parse(row["text"].as_str().unwrap(), TextRef::Points(&name))
            .map(|r| json!({"ok":{"argv":r.argv.iter().map(|s| s.borrowed().points().collect::<Vec<_>>()).collect::<Vec<_>>(),"definition_paths":r.definition_paths,"tree_inputs":r.tree_inputs,"absent_paths":r.absent_paths,"ci_inputs":r.ci_inputs}}))
            .unwrap_or_else(|e| json!({"origin":match e.origin { ErrorOrigin::Failure => "Failure", ErrorOrigin::Exception { class } => class },"reason":e.reason,"detail":e.detail.borrowed().points().collect::<Vec<_>>()}));
        assert_eq!(actual, row["expected"], "{row}");
    }
}

use super::*;
use crate::evidence::{legacy_policy::PolicyDocument, legacy_verify::value_checks_source};
use serde_json::{Value, json};

#[test]
fn lossless_run_maps_match_oracle_value_checks() {
    let script = r#"
import json,os,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p/'scripts/evidence-verify' if p.is_dir() else p
v=runpy.run_path(str(p)); rows=[]
for key in ['plain','k'+chr(0xd800),'k'+chr(0xdcff),'k'+chr(0x1f600),'long'*20]:
 for strong in ['strong',chr(0xd800),chr(0xdcff),'x\0y','x\ny']:
  weak='weak';rule={'command':['true'],'input_order':{key:[strong,weak]}}
  for note,run in [({key:strong},{key:weak}),({key:weak},{key:strong}),({key:strong},{key:strong}),({key:'bad'},{key:strong}),({key:strong},{}),({},{key:strong})]:
   policy={'version':1,'checks':{'check':{'trust_levels':['agent'],'kinds':{'wrapper':rule}}}}
   selected=v['policy_rules'](json.dumps(policy),'check','owner/repo')['kinds']['wrapper']
   try:v['value_checks'](selected,note,run,7);expected={'reason':'satisfied'}
   except v['Failure'] as e:expected={'reason':e.reason,'detail':list(map(ord,str(e))),'attempts':e.extra.get('attempts')}
   rows.append(dict(policy=json.dumps(policy),note=json.dumps(note),run=json.dumps(run),expected=expected))
 for expected_value in ['same',chr(0xd800),'x\0y']:
  rule={'command':['true'],'base_inputs':{key:'src'}}
  for note,run in [({key:expected_value},{key:expected_value}),({key:'bad'},{key:expected_value}),({key:expected_value},{}),({key:expected_value},{key:''})]:
   policy={'version':1,'checks':{'check':{'trust_levels':['agent'],'kinds':{'wrapper':rule}}}}
   selected=v['policy_rules'](json.dumps(policy),'check','owner/repo')['kinds']['wrapper']
   try:v['value_checks'](selected,note,run,7);expected={'reason':'satisfied'}
   except v['Failure'] as e:expected={'reason':e.reason,'detail':list(map(ord,str(e))),'attempts':e.extra.get('attempts')}
   rows.append(dict(policy=json.dumps(policy),note=json.dumps(note),run=json.dumps(run),expected=expected))
print(json.dumps(rows))
"#;
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.len(), 210);
    for row in rows {
        let rules = PolicyDocument::parse(row["policy"].as_str().unwrap(), "check")
            .unwrap()
            .into_rules("owner/repo")
            .unwrap();
        let note = Document::from_text(row["note"].as_str().unwrap()).unwrap();
        let run = Document::from_text(row["run"].as_str().unwrap()).unwrap();
        let note = ValidatedInputs::new(&note, note.root()).unwrap();
        let run = ValidatedInputs::new(&run, run.root()).unwrap();
        let actual = value_checks_source(&rules.kinds[0].1, InputSource::Document(note), &run, 7)
            .map(|()| json!({"reason":"satisfied"}))
            .unwrap_or_else(|e| json!({"reason":e.reason,"detail":e.detail.borrowed().points().collect::<Vec<_>>(),"attempts":e.attempts}));
        assert_eq!(actual, row["expected"], "{row}");
    }
}

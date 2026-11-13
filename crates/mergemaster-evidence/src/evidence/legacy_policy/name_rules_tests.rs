use super::*;
use crate::evidence::legacy_policy::{PolicyDocument, PolicyRules};
use serde_json::{Value, json};

fn summary(rules: &PolicyRules) -> Value {
    let kind = &rules.kinds[0].1;
    let command = |command: &[super::super::normalized_text::NormalizedText]| {
        command
            .iter()
            .map(|text| text.borrowed().points().collect::<Vec<_>>())
            .collect::<Vec<_>>()
    };
    json!({"require":rules.header.require,"command":command(&kind.inputs.command),
        "prefix":kind.runner_prefix.as_ref().map(|text| text.borrowed().points().collect::<Vec<_>>()),
        "level_command":command(&kind.by_level[0].1.inputs.command)})
}
#[test]
fn lossless_policy_names_normalize_through_the_pinned_rules() {
    let script = r#"
import json,pathlib,runpy,sys,tempfile
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
points=lambda s:list(map(ord,s))
for check in ['check','\ud800','\udfff','🦀','a\ud800b','\0','{repository}','{check}']:
 for repo in ['owner/repo','owner/{check}']:
  for mode in ['off','shadow','reject']:
   entry=dict(require=mode,trust_levels=['agent'],kinds=dict(wrapper=dict(command=['{repository}','{check}','{check}{check}','literal'],runner_prefix='producer/{repository}/{check}',by_level=dict(agent=dict(command=['level/{check}','{repository}'],events=['pull_request'])))))
   text=json.dumps(dict(version=1,checks={check:entry}),ensure_ascii=repo=='owner/repo' or any(0xd800<=ord(c)<=0xdfff for c in check))
   text.encode('utf-8')  # read_policy accepts strict UTF-8, not surrogatepass text.
   rules=v['policy_rules'](text,check,repo); kind=rules['kinds']['wrapper']
   expected=dict(require=rules['require'],command=[points(s) for s in kind['command']],prefix=points(kind['runner_prefix']),level_command=[points(s) for s in kind['by_level']['agent']['command']])
   cases.append(dict(text=text,check=points(check),repo=repo,expected=expected))
 for mutation in ['unknown','empty-kinds','missing-command','absent']:
  entry=dict(require='off',trust_levels=['agent'],kinds=dict(wrapper=dict(command=['true'])))
  if mutation=='unknown': entry['unknown']=True
  if mutation=='empty-kinds': entry['kinds']={}
  if mutation=='missing-command': del entry['kinds']['wrapper']['command']
  text=json.dumps(dict(version=1,checks={} if mutation=='absent' else {check:entry}))
  try: v['policy_rules'](text,check,'owner/repo'); raise AssertionError('expected refusal')
  except v['Failure'] as error: reason=error.reason
  except KeyError: reason='error'
  cases.append(dict(text=text,check=points(check),repo='owner/repo',expected=dict(reason=reason)))
namespace=v['read_policy'].__globals__; original=namespace['config_blob']
for invalid in [b'\xff',b'\xed\xa0\x80']:
 raw=b'{"version":1,"checks":{"'+invalid+b'":{}}}'
 with tempfile.NamedTemporaryFile() as file:
  file.write(raw); file.flush()
  namespace['config_blob']=lambda *args:pathlib.Path(file.name).read_bytes()
  try: v['read_policy']('unused','base'); raise AssertionError('invalid policy accepted')
  except v['Failure'] as error: reason=error.reason
  finally: namespace['config_blob']=original
 cases.append(dict(policy_bytes=list(raw),reason=reason))
print(json.dumps(cases))
"#;
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            script,
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
    assert_eq!(cases.len(), 82);
    for case in cases {
        if let Some(raw) = case.get("policy_bytes") {
            let bytes: Vec<u8> = serde_json::from_value(raw.clone()).unwrap();
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), bytes).unwrap();
            assert_eq!(
                std::fs::read_to_string(file.path()).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(case["reason"], "no_policy");
            continue;
        }
        let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
        let text = case["text"].as_str().unwrap();
        let repo = case["repo"].as_str().unwrap();
        let document = PolicyDocument::parse(text, check.as_slice()).unwrap();
        let TextRef::Points(borrowed) = document.check.text() else {
            panic!("not borrowed points")
        };
        assert!(std::ptr::eq(borrowed, check.as_slice()));
        let actual = document
            .into_rules(repo)
            .map(|rules| summary(&rules))
            .unwrap_or_else(|e| json!({"reason":e.reason}));
        assert_eq!(actual, case["expected"], "{case}");
        if let Some(scalar) = check
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
        {
            let scalar_result = PolicyDocument::parse(text, scalar.as_str())
                .unwrap()
                .into_rules(repo)
                .map(|rules| summary(&rules))
                .unwrap_or_else(|e| json!({"reason":e.reason}));
            assert_eq!(scalar_result, actual, "scalar API changed");
        }
    }
}

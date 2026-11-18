use super::*;
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyDocument};
use serde_json::{Value, json};
#[test]
fn accepted_base_values_match_no_lazy_oracle_and_bound_raw_sources() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import hashlib,json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);v=runpy.run_path(str(p/'scripts/evidence-verify' if p.is_dir() else p));rows=[]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[1])/fmt;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
 def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data).decode().strip()
 for size in [0,1048576,1048577]:
  blob=git('hash-object','-w','--stdin',data=b'\xff'*size);tree=git('mktree',data=('100644 blob '+blob+'\tfile\n').encode())
  scalar='refs/base/é'+str(size);base='refs/base/\udcc3\udca9'+str(size);git('update-ref',scalar,tree)
  kinds=dict(wrapper=dict(command=['run'],base_inputs={'z':'missing','\ud800':'file','a':'missing'}),observed=dict(command=['run'],base_inputs={'z':'file'}))
  policy=dict(version=1,checks=dict(check=dict(trust_levels=['agent'],kinds=kinds)))
  rules=v['policy_rules'](json.dumps(policy),'check','fixture')
  for revision in [base,'missing-ref',base+'\x00',base+'\ud800']:
   try:expected=dict(values=[[list(map(ord,k)),x] for k,x in v['base_input_values'](str(repo),revision,rules).items()])
   except Exception as e:expected=dict(origin=type(e).__name__,detail=list(map(ord,str(e))))
   rows.append(dict(repo=str(repo),base=list(map(ord,revision)),policy=json.dumps(policy),size=size,expected=expected))
print(json.dumps(rows))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 24);
    for row in rows {
        let points: Vec<u32> = serde_json::from_value(row["base"].clone()).unwrap();
        let text = row["policy"].as_str().unwrap();
        let rules = PolicyDocument::parse(text, "check")
            .unwrap()
            .into_rules("fixture")
            .unwrap();
        let result = base_input_values(
            Path::new(row["repo"].as_str().unwrap()),
            TextRef::Points(&points),
            Some(&rules),
        );
        if row["size"] == 1048577
            && row["expected"]
                .get("values")
                .is_some_and(|v| v[0][1] != "absent")
        {
            let error = result.err().unwrap();
            let spec = NormalizedText::concat(
                [TextRef::Points(&points), TextRef::Str(":file")].into_iter(),
            );
            assert_eq!(error.resource, Some(SourceResource::RawBlob(spec)));
            assert_eq!(error.origin, ErrorOrigin::Failure);
            assert_eq!(error.reason, "error");
            assert!(
                error.detail.borrowed().points().eq(points
                    .iter()
                    .copied()
                    .chain(":file exceeds 1048576 bytes".chars().map(u32::from)))
            );
        } else {
            let actual = match result {
                Ok(values) => {
                    json!({"values":values.into_iter().map(|(k,v)| json!([k.points().collect::<Vec<_>>(),v])).collect::<Vec<_>>()})
                }
                Err(e) => match e.origin {
                    ErrorOrigin::Exception { class } => {
                        json!({"origin":class,"detail":e.detail.borrowed().points().collect::<Vec<_>>()})
                    }
                    ErrorOrigin::Failure => panic!("unexpected failure"),
                },
            };
            assert_eq!(actual, row["expected"], "{row}");
        }
    }
    assert!(
        base_input_values(Path::new("\0"), TextRef::Str("\0"), None)
            .unwrap()
            .is_empty()
    );
}

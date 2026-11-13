use super::*;
use crate::evidence::{
    legacy_policy::PolicyDocument,
    legacy_verify::lane_git::{RequiredLane, required_lane},
};
use serde_json::{Value, json};
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

#[test]
fn required_git_bindings_and_eager_lanes_match_oracle() {
    let script = r#"
import hashlib,json,os,pathlib,runpy,subprocess,sys
from datetime import datetime,timezone
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]; blobs=[]
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[2])/fmt; root.mkdir(); key=root/'key'
 subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 keys=root/'keys'; keys.write_text('agent/fixture '+key.with_suffix('.pub').read_text())
 for check in ['check','\ud800','😀']:
  for name in ['no-file','eager-good','wrong-bound','missing-bound','wrong-definition','changed-definition','tree-lane','no-lane','malformed','missing-definition']:
   repo=root/str(len(cases)); subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
   def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
   git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
   def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
   def tree(files):
    rows=b''.join(('100644 blob '+blob(data)+'\t').encode()+path+b'\0' for path,data in sorted(files.items()))
    return git('mktree','-z',data=rows).decode().strip()
   content=b'x'*(3*1024*1024); digest=hashlib.sha256(content).hexdigest()
   files={b'def':b'base',b'bound':content,b'empty':b'',b'path-\xff':b'nonutf8'}
   base_tree=tree(files); base=git('commit-tree',base_tree,data=b'base').decode().strip()
   if name in ['changed-definition','tree-lane']: files[b'def']=b'changed'
   current=tree(files); subject=git('commit-tree',current,'-p',base,data=b'candidate').decode().strip()
   lane_text=json.dumps(dict(version=1,lanes={check:dict(argv=['true'],definition_paths=['absent' if name=='missing-definition' else 'def'])}))
   if name=='malformed': lane_text='{'
   if name=='no-lane': lane_text=json.dumps(dict(version=1,lanes={}))
   lane_file=None if name=='no-file' else (lane_text,base)
   try: lane=v['lane_for'](str(repo),current,lane_file,check); eager=None
   except v['Failure'] as e: lane=None; eager=dict(kind='missing' if e.reason=='no_lane' else 'global',reason=e.reason)
   kind=dict(command=['true'],bind_inputs={'bound':'absent' if name=='missing-bound' else 'bound'})
   if name=='tree-lane': kind['by_level']={'agent':dict(command=['true'],events=['pull_request'],lane='tree',bind_inputs={'bound':'bound'})}
   policy=json.dumps(dict(version=1,checks={check:dict(require='reject',trust_levels=['agent'],kinds={'wrapper':kind})})); rules=v['policy_rules'](policy,check,'fixture')
   inputs=dict(bound='wrong' if name=='wrong-bound' else digest,event_name='pull_request')
   if lane: inputs['lane_definition_sha256']='wrong' if name=='wrong-definition' else lane['tree_sha256'] if name=='tree-lane' else lane['sha256']
   value=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=subject,digest=dict(gitTree=current))],
    predicate=dict(schema_version=1,tier='full',change_id='joined',signer='agent/fixture',observed_at='2026-01-01T00:04:00Z',
     observed=dict(kind='tests',runner='wrapper',inputs=inputs,checks={check:dict(command=['true'],exit_code=0,output_sha256='0'*64)})))
   note=tree({current.encode():json.dumps(value).encode()})
   commit=git('-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',note,'-p',subject,data=b'record').decode().strip()
   git('update-ref','refs/tags/evidence/'+current+'/'+commit,commit)
   expected=eager
   if expected is None:
    try:
     result=v['verify'](str(repo),current,check,str(keys),None,rules=rules,lane=lane,now=datetime(2026,1,1,0,5,tzinfo=timezone.utc))
     expected=dict(kind='satisfied',record=result['record'],signer=result['signer'],tier=list(map(ord,result['tier'])))
    except v['Failure'] as e: expected=dict(kind='refusal',reason=e.reason,attempts=e.extra.get('attempts',0))
   reason={'wrong-bound':'wrong_input','missing-bound':'wrong_input','wrong-definition':'wrong_definition','changed-definition':'definition_changed','no-lane':'no_lane','malformed':'error','missing-definition':'error'}.get(name)
   assert expected.get('reason')==reason,(name,expected)
   cases.append(dict(repo=str(repo),tree=current,keys=str(keys),check=list(map(ord,check)),policy=policy,lane=None if lane_file is None else lane_text,base=base,name=fmt+'/'+ascii(check)+'/'+name,expected=expected))
   if check=='check' and name=='no-file':
    for path in [b'bound',b'empty',b'path-\xff',b'absent',b'']:
     blobs.append(dict(repo=str(repo),tree=current,path=path.hex(),expected=v['blob_sha256'](str(repo),current,os.fsdecode(path))))
    blobs.append(dict(repo=str(root/'absent'),tree=current,path=b'bound'.hex(),expected=v['blob_sha256'](str(root/'absent'),current,'bound')))
print(json.dumps(dict(cases=cases,blobs=blobs)))
"#;
    let root = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new("python3");
    crate::gate::git::sanitize(&mut command);
    let output = command
        .env("HOME", root.path())
        .env("GNUPGHOME", root.path())
        .env("XDG_CONFIG_HOME", root.path())
        .args([
            "-c",
            script,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
        ])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixtures: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fixtures["cases"].as_array().unwrap().len(), 60);
    for case in fixtures["cases"].as_array().unwrap() {
        let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
        let rules = PolicyDocument::parse(case["policy"].as_str().unwrap(), check.as_slice())
            .unwrap()
            .into_rules("fixture")
            .unwrap();
        let q = Request {
            repo: Path::new(case["repo"].as_str().unwrap()),
            tree: case["tree"].as_str().unwrap(),
            check: check.as_slice().into(),
            keys: case["keys"].as_str().unwrap(),
            inputs: None,
            crate_key: None,
        };
        let lane_file = case["lane"]
            .as_str()
            .map(|text| (text, case["base"].as_str().unwrap()));
        let mut clock = 1_767_225_900_000_000i64;
        let actual = match required_lane(q.repo, q.tree, lane_file, q.check, None) {
            Err(e) => json!({"kind":"global","reason":e.reason}),
            Ok(RequiredLane::Missing(e)) => json!({"kind":"missing","reason":e.reason}),
            Ok(RequiredLane::Ready(lane)) => {
                match required_git(&q, &rules, lane.as_ref(), &mut clock) {
                    Err(e) => json!({"kind":"refusal","reason":e.reason,"attempts":e.attempts}),
                    Ok(record) => {
                        let facts = DocumentFacts::for_check(
                            &record.candidate.statement,
                            &check,
                            &record.principal,
                        )
                        .unwrap();
                        json!({"kind":"satisfied","record":record.candidate.commit,"signer":record.principal,"tier":facts.tier})
                    }
                }
            }
        };
        assert_eq!(actual, case["expected"], "{}", case["name"]);
    }
    assert_eq!(fixtures["blobs"].as_array().unwrap().len(), 12);
    for blob in fixtures["blobs"].as_array().unwrap() {
        let mut provider = GitProvider {
            repo: Path::new(blob["repo"].as_str().unwrap()),
            tree: blob["tree"].as_str().unwrap(),
        };
        let path = OsString::from_vec(hex::decode(blob["path"].as_str().unwrap()).unwrap());
        assert_eq!(
            json!(provider.blob_sha256(Path::new(&path)).unwrap()),
            blob["expected"]
        );
    }
}

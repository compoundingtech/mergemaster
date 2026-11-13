use super::*;
use serde_json::{Value, json};
#[test]
fn required_lane_adapter_matches_actual_git_in_both_formats() {
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); root=pathlib.Path(sys.argv[2]); cases=[]
env=dict(os.environ,GIT_AUTHOR_NAME='fixture',GIT_COMMITTER_NAME='fixture',GIT_AUTHOR_EMAIL='fixture@example.invalid',GIT_COMMITTER_EMAIL='fixture@example.invalid')
for fmt in ['sha1','sha256']:
 for index,name in enumerate(['check','\ud800','🦀']):
  repo=root/(fmt+str(index)); subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],env=env,check=True)
  def git(*args,input=None): return subprocess.check_output(['git','-C',str(repo),*args],input=input,env=env,stderr=subprocess.DEVNULL)
  def tree(files):
   git('read-tree','--empty')
   for path,data in files.items():
    oid=git('hash-object','-w','--stdin',input=data).decode().strip(); git('update-index','--add','--cacheinfo','100644,'+oid+','+path)
   return git('write-tree').decode().strip()
  def commit(files,label,parent=None):
   oid=tree(files); return git('commit-tree',oid,*([] if parent is None else ['-p',parent]),input=label.encode()).decode().strip(),oid
  text=json.dumps(dict(version=1,lanes={name:dict(argv=['run'],definition_paths=['def'])}))
  files={'def':b'base','.st/required-lanes.json':text.encode()}
  base,bt=commit(files,'base'); accepted,at=commit(files,'accepted',base)
  changed=tree(dict(files,**{'def':b'changed'})); other=tree(dict(files,other=b'extra'))
  def emit(label,text=text,accepted=accepted,candidate=bt,lane_base=None,lookup=name,none=False,repository=None):
   repository=str(repo) if repository is None else str(repository)
   try:
    result=v['lane_for'](repository,candidate,None if none else (text,accepted),lookup,lane_base)
    if result is not None: result=dict(result,changed=[list(os.fsencode(p)) for p in result['changed']])
    expected=dict(kind='ready',definition=result)
   except v['Failure'] as error: expected=dict(kind='missing' if error.reason=='no_lane' else 'error',reason=error.reason)
   target='ready' if label in ['unchanged','changed','other','ancestor','no-file-bypass','preferred-path'] else 'missing' if label=='missing' else 'error'
   assert expected['kind']==target,(label,expected)
   if target=='ready': assert (expected['definition'] is None)==none,(label,expected)
   if target!='ready': assert expected['reason']==('no_lane' if target=='missing' else 'definition_changed' if label in ['raw-definition-changed','missing-branchpoint-file'] else 'error'),(label,expected)
   if label=='changed': assert expected['definition']['changed']==[list(b'def')],expected
   cases.append(dict(label=fmt+'/'+ascii(name)+'/'+label,repo=repository,tree=candidate,text=None if none else text,accepted=accepted,name=list(map(ord,lookup)),base=lane_base,expected=expected))
  emit('unchanged'); emit('changed',candidate=changed); emit('other',candidate=other)
  emit('ancestor',lane_base=base); emit('missing',lookup=name+'-missing')
  emit('no-file-bypass',none=True,lane_base='invalid',candidate='invalid',repository=root/'absent')
  emit('invalid-ancestor',lane_base='--invalid'); emit('missing-commit-before-missing-lane',accepted='0'*len(base),lookup=name+'-missing')
  emit('malformed',text='{')
  unrelated,_=commit(files,'unrelated'); emit('not-ancestor',lane_base=unrelated)
  different=json.loads(text); different['lanes'][name]['absent_paths']=[]; different=json.dumps(different)
  edited,_=commit(dict(files,**{'.st/required-lanes.json':different.encode()}),'edited',base)
  emit('raw-definition-changed',text=different,accepted=edited,lane_base=base)
  nofile,_=commit({'def':b'base'},'no file'); after,_=commit(files,'after missing file',nofile)
  emit('missing-branchpoint-file',accepted=after,lane_base=nofile)
  for label,field,value in [('missing-definition','definition_paths',['missing']),('absent-present','absent_paths',['def'])]:
   bad=json.loads(text); bad['lanes'][name][field]=value; emit(label,text=json.dumps(bad))
  preferred={'.fractal/required-lanes.json':text.encode(),'def':b'base'}
  pref,pt=commit(preferred,'preferred'); pref_after,_=commit(preferred,'preferred after',pref)
  emit('preferred-path',accepted=pref_after,lane_base=pref,candidate=pt)
print(json.dumps(cases))
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
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle"),
        ])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 90);
    for case in cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let result = required_lane(
            Path::new(case["repo"].as_str().unwrap()),
            case["tree"].as_str().unwrap(),
            case["text"]
                .as_str()
                .map(|text| (text, case["accepted"].as_str().unwrap())),
            name.as_slice(),
            case["base"].as_str(),
        );
        let actual = match result {
            Ok(RequiredLane::Ready(definition)) => {
                json!({"kind":"ready","definition":definition.map(|d| json!({"sha256":d.sha256,"tree_sha256":d.tree_sha256,"changed":d.changed}))})
            }
            Ok(RequiredLane::Missing(e)) => json!({"kind":"missing","reason":e.reason}),
            Err(e) => json!({"kind":"error","reason":e.reason}),
        };
        assert_eq!(actual, case["expected"], "{}", case["label"]);
    }
}

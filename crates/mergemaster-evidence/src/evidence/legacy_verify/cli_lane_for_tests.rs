use super::*;
use crate::evidence::legacy_policy::ErrorOrigin;
use serde_json::{Value, json};
fn actual(case: &Value) -> Value {
    let accepted: Vec<u32> = serde_json::from_value(case[3].clone()).unwrap();
    let check: Vec<u32> = serde_json::from_value(case[4].clone()).unwrap();
    let base: Option<Vec<u32>> = serde_json::from_value(case[5].clone()).unwrap();
    let text = case[2]
        .as_str()
        .map(|p| std::fs::read_to_string(p).unwrap());
    match lane_for(
        Path::new(case[0].as_str().unwrap()),
        TextRef::Str(case[1].as_str().unwrap()),
        text.as_deref()
            .map(|text| (text, TextRef::Points(&accepted))),
        TextRef::Points(&check),
        base.as_deref().map(TextRef::Points),
    ) {
        Ok(Some(lane)) => {
            json!(["ok", {"sha256":lane.sha256,"tree_sha256":lane.tree_sha256,"changed":lane.changed}])
        }
        Ok(None) => json!(["ok", null]),
        Err(e) if case[7] == true => {
            assert_eq!(
                e.resource,
                Some(SourceResource::LaneJson(PolicyResource::SourceBytes))
            );
            assert_eq!(e.origin, ErrorOrigin::Failure);
            json!(["resource", e.reason, e.detail.to_string()])
        }
        Err(e) => json!([
            match e.origin {
                ErrorOrigin::Failure => "Failure",
                ErrorOrigin::Exception { class } => class,
            },
            e.reason,
            e.detail.borrowed().points().collect::<Vec<_>>()
        ]),
    }
}
#[test]
fn cli_lane_resolution_matches_original_order_transports_and_bounds() {
    if let Ok(case) = std::env::var("MM_LANE_FOR_CASE") {
        let case: Value = serde_json::from_str(&case).unwrap();
        assert_eq!(actual(&case), case[6]);
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p if p.is_dir() else p.parent.parent
m=runpy.run_path(str(p/'scripts/evidence-verify'));root=pathlib.Path(sys.argv[1]);cases=[]
os.environ.update(GIT_AUTHOR_NAME='fixture',GIT_AUTHOR_EMAIL='fixture@invalid',GIT_COMMITTER_NAME='fixture',GIT_COMMITTER_EMAIL='fixture@invalid')
def add(repo,tree,text,accepted,check,base,resource=False):
 try:
  result=m['lane_for'](str(repo),tree,None if text is None else (text,accepted),check,base)
  if result:result['changed']=[list(n.encode(errors='surrogateescape')) for n in result['changed']]
  expected=['ok',result]
 except m['Failure'] as e:expected=['Failure',e.reason,list(map(ord,e.detail))]
 except Exception as e:expected=[type(e).__name__,'error',list(map(ord,str(e)))]
 if resource:
  assert expected[0]=='ok';expected=['resource','error','lane JSON source exceeds 1048576 bytes']
 file=root/('text'+str(len(cases)))
 if text is not None:file.write_text(text)
 cases.append([str(repo),tree,str(file) if text is not None else None,list(map(ord,accepted)),list(map(ord,check)),None if base is None else list(map(ord,base)),expected,resource])
for width in ['sha1','sha256']:
 for layout in ['.st','.fractal']:
  repo=root/(width+layout);repo.mkdir();subprocess.run(['git','init','-q','--object-format='+width,str(repo)],check=True)
  def git(*args):return subprocess.check_output(['git','-C',str(repo),'-c','commit.gpgsign=false',*args]).strip().decode()
  def commit(parent=None):
   git('add','.');tree=git('write-tree');return tree,git('commit-tree',tree,*(['-p',parent] if parent else []),'-m','fixture')
  (repo/'src').write_text('old');_,pre=commit()
  check='check'+chr(0xd800);text=json.dumps(dict(version=1,lanes={check:dict(argv=['run',chr(0xdfff)],definition_paths=['src'])}))
  directory=repo/layout;directory.mkdir();path=directory/'required-lanes.json';path.write_text(text);old,branch=commit(pre)
  (repo/'src').write_text('new');tree,accepted=commit(branch);git('update-ref','refs/heads/main',accepted);git('update-ref','refs/heads/é',accepted)
  _,unrelated=commit()
  for rev in [accepted,'main',chr(0xdcc3)+chr(0xdca9)]:add(repo,old,text,rev,check,None)
  assert all(c[6][0]=='ok' and c[6][1] for c in cases[-3:])
  add(repo,tree,None,'missing',check,'bad')
  for base in [branch,'','HEAD',branch[:12],branch.upper(),'x\0',chr(0xd800),unrelated,pre]:add(repo,tree,text,accepted,check,base)
  for changed,name,base in [(text,check,branch),(text,'missing',branch),(text,'missing',None),('{',check,None),('{',check,branch),(text.replace('run','other'),check,branch)]:add(repo,tree,changed,accepted,name,base)
  assert cases[-6][6][0]=='ok' and cases[-6][6][1]
  add(repo,tree,'{','missing',check,None)
  for size in [1048576,1048577]:
   padded=text+' '*(size-len(text));path.write_text(padded);_,large=commit(accepted);add(repo,tree,padded,large,check,large,size>1048576)
shim=root/'shim';shim.mkdir();program=shim/'git'
program.write_text('#!'+sys.executable+'''\nimport os,sys
if 'ls-tree' in sys.argv:os.write(1,b'100644 blob '+b'a'*40+b'\\t.st/required-lanes.json\\0')
if 'show' in sys.argv:sys.exit(1)
''');program.chmod(0o700);os.environ['PATH']=str(shim)
add('.', 'a'*40, '{}','a'*40,'check','b'*40)
assert cases[-1][6][:2]==['Failure','error']
assert ''.join(map(chr,cases[-1][6][2]))=='could not read lane file at '+('b'*40)+':.st/required-lanes.json'
print(json.dumps(cases))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let shim = cases.pop().unwrap();
    assert_eq!(cases.len(), 88);
    for case in cases {
        assert_eq!(actual(&case), case[6]);
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "evidence::legacy_verify::cli_lane_for::tests::cli_lane_resolution_matches_original_order_transports_and_bounds", "--nocapture"]).env("PATH",root.path().join("shim")).env("MM_LANE_FOR_CASE",shim.to_string()).output().unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

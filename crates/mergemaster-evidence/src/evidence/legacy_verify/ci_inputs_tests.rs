use super::*;
use std::ffi::OsString;
type Row = (Vec<String>, String, Vec<u8>, u8);

#[test]
fn wave2_ci_inputs_and_import_helpers_match_pinned_python_bytes() {
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
v=runpy.run_path(str(pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify'))
root=pathlib.Path(sys.argv[1]);rows=[]
def row(argv,stdin,operation):
 try:
  value=operation();code=0
 except v['Failure'] as error:
  value=dict(reason=error.reason,detail=error.detail);code=3
 except Exception as error:
  value=dict(reason='error',detail=type(error).__name__+': '+str(error));code=3
 rows.append([argv,stdin,list((json.dumps(value,indent=2)+'\n').encode()),code])
for fmt in ['sha1','sha256']:
 repo=root/fmt;repo.mkdir()
 def git(*args):return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
 git('init','--object-format='+fmt);git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
 (repo/'.fractal').mkdir();(repo/'.st').mkdir();(repo/'ci').mkdir()
 (repo/'ci/job.yml').write_text('jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n')
 (repo/'.st/input.json').write_text('{"key":"legacy"}');(repo/'.fractal/input.json').write_text('{"key":"preferred"}')
 (repo/'input.json').write_text('{"key":{"b":2,"a":1},"empty":{},"null":null}')
 (repo/'invalid.json').write_text('not JSON');(repo/'binary').write_bytes(b'\xff');(repo/'source').write_text('base')
 git('add','.');git('commit','-m','base');base=git('rev-parse','HEAD');base_tree=git('rev-parse','HEAD^{tree}')
 (repo/'unrelated').write_text('other');git('add','.');git('commit','-m','unrelated');other=git('rev-parse','HEAD')
 (repo/'source').write_text('changed');git('add','.');git('commit','-m','changed');changed=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
 inputs=[[],['source'],['.'],['!missing'],['missing'],['missing','missing'],['ci'],['ci/job.yml::jobs.test'],['ci/job.yml::jobs.renamed'],['input.json::key'],['input.json::empty'],['input.json::null'],['input.json::absent'],['.st/input.json::key'],['invalid.json::key'],['binary::key'],['!missing','.','source']]
 for ci in inputs:
  row(['unresolved-ci-inputs','--repo',str(repo),'--tree',tree,*sum((['--input',i] for i in ci),[])],'',lambda ci=ci:v['unresolved_ci_inputs'](str(repo),tree,ci))
  for revisions in [[],[base],[base,other],[base,changed],[base,'missing'],['missing',base]]:
   argv=['ci-inputs','--repo',str(repo),*sum((['--input',i] for i in ci),[]),*sum((['--revision',r] for r in revisions),[])]
   row(argv,'',lambda ci=ci,revisions=revisions:dict(unchanged=v['ci_inputs_unchanged'](str(repo),ci,revisions)))
 for expression in ['HEAD','HEAD~1',base,'missing']:
  for ci in [['source'],['input.json::key'],['.st/input.json::key'],['ci/job.yml::jobs.test']]:
   row(['unresolved-ci-inputs','--repo',str(repo),'--tree',expression,*sum((['--input',i] for i in ci),[])],'',lambda ci=ci,expression=expression:v['unresolved_ci_inputs'](str(repo),expression,ci))
 for revisions in [['HEAD'],['HEAD~1',other],['HEAD',base],['HEAD','bad^{']]:
  for ci in [['source'],['input.json::key'],['.st/input.json::key'],['ci/job.yml::jobs.test']]:
   row(['ci-inputs','--repo',str(repo),*sum((['--input',i] for i in ci),[]),*sum((['--revision',r] for r in revisions),[])],'',lambda ci=ci,revisions=revisions:dict(unchanged=v['ci_inputs_unchanged'](str(repo),ci,revisions)))
 row(['select-part','--path','x.json','--selector','key'],'{"key":1e400}',lambda:list(v['select_part']('{"key":1e400}','x.json','key')))
 for value in [1.5,float('nan'),float('inf'),-float('inf'),-0.0,10**120,{'z':[1.5,{'b':2,'a':1}],'a':0},'\ud800',{'z':1,'\ud800':2}]:
  content=json.dumps({'key':value})
  row(['select-part','--path','x.json','--selector','key'],content,lambda content=content:list(v['select_part'](content,'x.json','key')))
 for path,selector,content in [('x.json','key','{"key":{"z":2,"a":1}}'),('x.json','missing','{}'),('x.json','key','not JSON'),('x.json','null','{"null":null}'),('x.json','key','{"key":"caf\u00e9"}'),('ci.yml','jobs.test',(repo/'ci/job.yml').read_text()),('ci.yml','jobs.absent',(repo/'ci/job.yml').read_text())]:
  def select(content=content,path=path,selector=selector):
   selected=v['select_part'](content,path,selector)
   return list(selected) if selected is not None else None
  row(['select-part','--path',path,'--selector',selector],content,select)
 rules_cases=[dict(argv=['true'],definition_paths=['source']),dict(argv=['caf\u00e9','\udcff'],definition_paths=['source'],tree_inputs=['ci'],absent_paths=['absent'],ci_inputs=['ci/job.yml::jobs.test']),dict(argv=[],definition_paths=['source']),dict(argv=['true'],definition_paths=['missing']),dict(argv=['true'],definition_paths=['source'],absent_paths=['source'])]
 for rules in rules_cases:
  content=json.dumps(dict(version=1,lanes={'x':rules}))
  row(['lane-rules','--check','x'],content,lambda content=content:v['lane_rules'](content,'x'))
  row(['lane-definition','--repo',str(repo),'--base-tree',base_tree,'--tree',tree,'--check','x'],content,lambda content=content:v['lane_definition'](str(repo),base_tree,tree,v['lane_rules'](content,'x')))
 row(['lane-rules','--check','missing'],content,lambda:v['lane_rules'](content,'missing'))
 row(['lane-rules','--check','x'],'not JSON',lambda:v['lane_rules']('not JSON','x'))
 for name,initial,updated in [('float',1.5,2.5),('nan',float('nan'),float('inf')),('surrogate','\ud800','\udfff')]:
  (repo/'extension.json').write_text(json.dumps({'key':initial}));git('add','.');git('commit','-m',name+' initial');start=git('rev-parse','HEAD')
  (repo/'unrelated').write_text(name);git('add','.');git('commit','-m',name+' unrelated');same=git('rev-parse','HEAD')
  (repo/'extension.json').write_text(json.dumps({'key':updated}));git('add','.');git('commit','-m',name+' changed');end=git('rev-parse','HEAD')
  for revisions in [[start],[start,same],[start,end]]:
   row(['ci-inputs','--repo',str(repo),'--input','extension.json::key',*sum((['--revision',r] for r in revisions),[])],'',lambda revisions=revisions:dict(unchanged=v['ci_inputs_unchanged'](str(repo),['extension.json::key'],revisions)))
 git('update-ref','HEAD',changed)
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
    let output = crate::pinned_python::command()
        .args(["-B", "-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<Row> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 378);
    for (argv, stdin, stdout, code) in rows {
        let actual =
            super::super::cli_helper::run(argv.iter().map(OsString::from), &mut stdin.as_bytes())
                .unwrap();
        assert_eq!(actual.code, code, "{argv:?}");
        assert_eq!(actual.stdout.as_bytes(), stdout, "{argv:?}");
        assert!(actual.stderr.is_empty(), "{argv:?}: {}", actual.stderr);
    }
}

#[test]
fn wave2_revision_resolution_does_not_short_circuit_missing_inputs() {
    let root = tempfile::tempdir().unwrap();
    crate::gate::git::git(root.path(), &["init"]).unwrap();
    let error =
        ci_inputs_unchanged(root.path(), &["absent".into()], &["missing".into()]).unwrap_err();
    assert!(error.detail.to_string().contains("git rev-parse:"));
}

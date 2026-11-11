use super::*;
#[test]
fn collection_matches_oracle_and_budget_refusal_aborts_the_check() {
    let script = r#"
import ast,copy,json,pathlib,runpy,subprocess,sys
source=pathlib.Path(sys.argv[1]+'/scripts/evidence-verify'); o=runpy.run_path(str(source))
f=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='verified')
w=next(n for n in f.body if isinstance(n,ast.With))
w.body=[n for n in w.body if n.lineno<982]+[ast.Return(ast.Name('mine',ast.Load()))]
f.body=[w]; exec(compile(ast.fix_missing_locations(ast.Module([f],[])),str(source),'exec'),o)
results=[]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[2])/fmt
 subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
 def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
 def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
 def tree(data=b''): return git('mktree',data=data).decode().strip()
 def commit(t,parent='',message='subject'):
  raw='tree '+t+'\n'+('parent '+parent+'\n' if parent else '')+'author A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\n'+message+'\n'
  return git('hash-object','-t','commit','-w','--stdin',data=raw.encode()).decode().strip()
 first=tree(); second=tree(('100644 blob '+blob(b'other')+'\tfile\n').encode())
 def add(t,name,key,layout='tags',wide=False):
  subject=commit(t)
  value={'_type':o['STATEMENT_TYPE'],'predicateType':o['PREDICATE_TYPE'],'subject':[{'name':subject,'digest':{'gitTree':t}}],
   'predicate':{'schema_version':1,'change_id':'change','tier':'full','signer':None,'observed_at':'2026-01-01T00:00:00Z',
   'observed':{'kind':'tests','runner':'r','checks':{},'inputs':{'crate':name,'source_inputs':key}}}}
  if wide: value['extra']=[0]*500000
  data=json.dumps(value,separators=(',',':')).encode(); assert len(data)<=1048576
  record=commit(tree(('100644 blob '+blob(data)+'\t'+t+'\n').encode()),subject,name)
  git('update-ref','refs/'+layout+'/evidence/'+t+'/'+record,record)
  return record
 a=add(first,'alpha',first); b=add(first,'beta',second)
 git('update-ref','refs/notes/evidence/'+first+'/'+a,a)
 legacy=add(first,'legacy',first); git('update-ref','-d','refs/tags/evidence/'+first+'/'+legacy)
 git('update-ref','refs/notes/evidence/'+legacy,legacy)
 invalid=commit(tree(('100644 blob '+blob(b'{')+'\t'+first+'\n').encode()),commit(first))
 git('update-ref','refs/tags/evidence/'+first+'/'+invalid,invalid)
 cross=add(second,'alpha',first); other=add(second,'beta',first); mismatch=add(second,'alpha',second)
 for record in [a,cross,other,mismatch]: git('update-ref','refs/tags/evidence/input/check/'+first+'/'+record,record)
 calls=[]
 for paths,crate in [(None,None),(['.'],None),(['missing'],None),([],None),(['.'],['alpha',first]),(None,['beta',first]),(None,['absent',first]),(['.'],['alpha',second])]:
  expected=[c for c,_ in o['verified'](str(repo),first,'check','unused',[],rules=None if paths is None else {'inputs':paths},crate_key=crate)]
  calls.append(dict(paths=paths,crate=crate,expected=expected))
 budget=tree(('100644 blob '+blob(b'budget')+'\tfile\n').encode())
 small=add(budget,'small',first)
 for n in range(3): add(budget,'wide'+str(n),first,'notes',True)
 expected=[c for c,_ in o['verified'](str(repo),budget,'check','unused',[])]
 assert len(expected)==4 and expected[0]==small
 results.append(dict(repo=str(repo),tree=first,empty='0'*len(first),budget=budget,small=small,calls=calls))
print(json.dumps(results))
"#;
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new("python3")
        .args(["-c", script, &oracle])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixtures: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for fixture in fixtures.as_array().unwrap() {
        let repo = Path::new(fixture["repo"].as_str().unwrap());
        let tree = fixture["tree"].as_str().unwrap();
        let mut collector = CandidateCollector::for_check();
        for call in fixture["calls"].as_array().unwrap() {
            let paths = call["paths"].as_array().map(|a| {
                a.iter()
                    .map(|s| s.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            });
            let crate_key = call["crate"]
                .as_array()
                .map(|a| (a[0].as_str().unwrap(), a[1].as_str().unwrap()));
            let actual = collector
                .collect(repo, tree, "check", paths.as_deref(), crate_key)
                .unwrap();
            assert_eq!(
                serde_json::json!(actual.records.iter().map(|c| &c.commit).collect::<Vec<_>>()),
                call["expected"]
            );
        }
        let initial = collector.collect(repo, tree, "check", None, None).unwrap();
        assert!(!initial.records.is_empty());
        for _ in 0..52 {
            let repeated = collector.collect(repo, tree, "check", None, None).unwrap();
            assert!(Arc::ptr_eq(
                &initial.records[0].statement,
                &repeated.records[0].statement
            ));
        }
        let failed = collector.collect(
            repo,
            fixture["budget"].as_str().unwrap(),
            "check",
            None,
            None,
        );
        assert!(matches!(failed, Err(e) if e.reason == "record-budget-exceeded"));
        for later in [tree, fixture["empty"].as_str().unwrap()] {
            assert!(
                matches!(collector.collect(repo, later, "check", None, None), Err(e) if e.reason == "record-budget-exceeded")
            );
        }
        assert!(
            !CandidateCollector::for_check()
                .collect(repo, tree, "check", None, None)
                .unwrap()
                .records
                .is_empty()
        );
    }
}

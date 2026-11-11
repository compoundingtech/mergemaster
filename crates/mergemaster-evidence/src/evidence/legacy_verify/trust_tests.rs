use super::*;
use crate::evidence::legacy_verify::statement::statement_of;
use std::sync::Arc;
#[test]
fn trust_partition_matches_oracle_and_propagates_errors() {
    let script = r#"
import ast,json,pathlib,runpy,subprocess,sys
source=pathlib.Path(sys.argv[1]+'/scripts/evidence-verify'); o=runpy.run_path(str(source))
f=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='verified')
w=next(n for n in f.body if isinstance(n,ast.With))
w.body=[n for n in w.body if 982<=n.lineno<=995]
w.body.append(ast.Return(ast.parse("result={'trusted':[[c,p] for c,s,p in trusted],'untrusted':untrusted,'degraded':[c for c,s in degraded]}").body[0].value))
f.name='partitioned'; f.body=[w]
exec(compile(ast.fix_missing_locations(ast.Module([f],[])),str(source),'exec'),o)
fixtures=[]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[2])/fmt
 subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
 def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
 git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
 key=repo/'key'; subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 keys=repo/'keys'; keys.write_text('fixture@example.invalid '+key.with_suffix('.pub').read_text())
 revocations=repo/'revocations'; revocations.write_text('')
 tree=git('mktree',data=b'').decode().strip()
 def signed(message): return git('-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',tree,data=message.encode()).decode().strip()
 good=signed('first'); later=signed('later')
 unsigned=git('commit-tree',tree,data=b'unsigned').decode().strip()
 forged=git('hash-object','-t','commit','-w','--stdin',data=git('cat-file','commit',good).replace(b'first',b'forged')).decode().strip()
 missing='f'*len(good)
 def statement(tier,signer): return {'_type':o['STATEMENT_TYPE'],'predicateType':o['PREDICATE_TYPE'],'subject':[{'name':unsigned,'digest':{'gitTree':tree}}],
  'predicate':{'schema_version':1,'change_id':'change','tier':tier,'signer':signer,'observed_at':'2026-01-01T00:00:00Z','observed':{'kind':'tests','runner':'r','checks':{}}}}
 mine=[(good,statement('full','fixture@example.invalid')),(missing,statement('degraded',None)),
  (unsigned,statement('full',None)),(forged,statement('full','fixture@example.invalid')),
  (good,statement('full','wrong@example.invalid')),(later,statement('test','fixture@example.invalid')),
  (good,statement('full',None)),(unsigned,statement('degraded','irrelevant'))]
 o['mine']=mine
 expected=o['partitioned'](str(repo),tree,'check',str(keys),[])
 fixtures.append(dict(repo=str(repo),tree=tree,keys=str(keys),revocations=str(revocations),candidates=mine,expected=expected,missing=missing))
print(json.dumps(fixtures))
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
    for f in fixtures.as_array().unwrap() {
        let repo = Path::new(f["repo"].as_str().unwrap());
        let keys = f["keys"].as_str().unwrap();
        let revocations = f["revocations"].as_str().unwrap();
        let candidates = || {
            f["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| Candidate {
                    commit: c[0].as_str().unwrap().into(),
                    statement: Arc::new(
                        statement_of(
                            &serde_json::to_vec(&c[1]).unwrap(),
                            f["tree"].as_str().unwrap(),
                        )
                        .unwrap()
                        .unwrap(),
                    ),
                })
                .collect::<Vec<_>>()
        };
        let groups = partition(repo, candidates(), keys, revocations).unwrap();
        assert_eq!(
            serde_json::json!({
                "trusted":groups.trusted.iter().map(|c| (&c.candidate.commit,&c.principal)).collect::<Vec<_>>(),
                "untrusted":groups.untrusted.iter().map(|c| (c.reason,&c.commit)).collect::<Vec<_>>(),
                "degraded":groups.degraded.iter().map(|c| &c.commit).collect::<Vec<_>>()
            }),
            f["expected"]
        );
        let mut input = candidates();
        input[1].statement = Arc::clone(&input[0].statement);
        assert!(matches!(partition(repo,input,keys,revocations),Err(e) if e.reason=="error"));
        assert!(
            matches!(partition(repo,candidates(),keys,"missing-policy"),Err(e) if e.reason=="error" && e.detail.contains("revocation"))
        );
        assert_eq!(
            partition(repo, Vec::new(), keys, "missing-policy")
                .unwrap()
                .trusted
                .len(),
            0
        );
    }
}

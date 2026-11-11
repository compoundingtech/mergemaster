use super::*;
#[test]
fn records_match_python_oracle() {
    let script = r#"
import copy,json,os,pathlib,runpy,subprocess,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]; cached=[]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[2])/fmt
 subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
 def git(*args,data=None):
  return subprocess.check_output(['git','-C',str(repo),*args],input=data,env=os.environ|{'GIT_NO_LAZY_FETCH':'1','GIT_NO_REPLACE_OBJECTS':'1'})
 def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
 def tree(rows): return git('mktree',data=''.join(m+' '+kind+' '+oid+'\t'+p+'\n' for m,kind,oid,p in rows).encode()).decode().strip()
 def commit(t,parents=(),message='record'):
  raw='tree '+t+'\n'+''.join('parent '+p+'\n' for p in parents)+'author A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\n'+message+'\n'
  return git('hash-object','-t','commit','-w','--stdin',data=raw.encode()).decode().strip()
 empty=tree([]); subject=commit(empty); missing='f'*len(subject)
 valid={'_type':o['STATEMENT_TYPE'],'predicateType':o['PREDICATE_TYPE'],
  'subject':[{'name':subject,'digest':{'gitTree':empty}}],
  'predicate':{'schema_version':1,'change_id':'change','tier':'full','signer':None,
  'observed_at':'2026-01-01T00:00:00Z','observed':{'kind':'tests','runner':'r','checks':{}}}}
 def add(name,value=valid,parents=None,rows=None,path=empty,mode='100644',encoding='utf-8',expected_tree=empty,padding=0,message='record',shallow=False,depth=0):
  data=json.dumps(value).encode(encoding) if not isinstance(value,bytes) else value
  if depth: data=data[:-1]+b',"extra":'+b'['*(depth-1)+b'0'+b']'*(depth-1)+b'}'
  data+=b' '*max(0,padding-len(data)); b=blob(data)
  t=tree(rows if rows is not None else [(mode,'blob',b,path)])
  c=commit(t,[subject] if parents is None else parents,message)
  if shallow: (repo/'shallow').write_text(c+'\n')
  expected=o['read_statement'](str(repo),c,expected_tree) is not None
  if depth in [497,498]:
   ref='refs/tags/evidence/'+empty+'/'+c; git('update-ref',ref,c)
   keys=repo/'keys'; keys.write_text('')
   cli=subprocess.run([sys.executable,sys.argv[1]+'/scripts/evidence-verify','--repo',str(repo),'--tree',empty,'--check','check','--keys',str(keys)],env=os.environ|{'TMPDIR':str(repo)},capture_output=True,text=True)
   result=json.loads(cli.stdout); git('update-ref','-d',ref)
   assert cli.returncode==1 and result['reason']==('error' if depth==498 else 'bad_signature')
   assert ('RecursionError' in result['detail'])==(depth==498)
  cases.append(dict(repo=str(repo),name=fmt+'-'+name,commit=c,tree=expected_tree,expected=expected,oversize=padding>1024*1024,listing_over=name=='listing-over',depth=depth))
  return c
 add('valid'); add('unbound',expected_tree=None); add('wrong-request',expected_tree='0'*len(subject))
 add('empty',rows=[]); b=blob(b'x'); add('multiple',rows=[('100644','blob',b,'a'),('100644','blob',b,'b')])
 add('executable',mode='100755'); add('symlink',mode='120000'); add('bad-path',path='not-an-oid')
 add('subtree',rows=[('040000','tree',tree([('100644','blob',b,empty)]),'nested')])
 add('listing-over',path='x'*(1024*1024))
 add('malformed-json',value=b'{'); add('no-parent',parents=[]); add('wrong-parent',parents=[missing]); add('two-parents',parents=[subject,missing])
 v=copy.deepcopy(valid); v['subject'][0]['name']=missing; add('missing-subject',value=v,parents=[missing])
 v=copy.deepcopy(valid); v['subject'][0]['digest']['gitTree']='0'*len(subject); add('wrong-digest',value=v)
 other=commit(tree([('100644','blob',b,'file')]))
 v=copy.deepcopy(valid); v['subject'][0]['name']=other; add('present-wrong-tree',value=v,parents=[other])
 add('utf16',encoding='utf-16'); add('message-parent',message='parent '+missing)
 add('shallow',shallow=True)
 add('cap-exact',padding=1024*1024); add('cap-over',padding=1024*1024+1)
 for depth in [256,257,497,498]: add('depth-'+str(depth),depth=depth)
 good=next(c['commit'] for c in cases if c['name']==fmt+'-valid')
 bad=next(c['commit'] for c in cases if c['name']==fmt+'-malformed-json'); wrong='0'*len(subject)
 first=o['load'](str(repo),good); first['predicate']['change_id']='mutated'
 flags={'independent':o['load'](str(repo),good)['predicate']['change_id']=='change'}
 assert o['load'](str(repo),bad) is None and o['load'](str(repo),good,wrong) is None
 moved=repo.with_name(fmt+'-moved'); repo.rename(moved)
 def fails(path,c,t=None):
  try: o['load'](path,c,t)
  except o['Failure']: return True
  return False
 flags.update(positive_hit=o['load'](str(repo),good) is not None,negative_hit=o['load'](str(repo),bad) is None,
  tree_hit=o['load'](str(repo),good,wrong) is None,tree_identity=fails(str(repo),good,empty),
  commit_identity=fails(str(repo),missing),repo_identity=fails(str(moved/'absent'),good),lexical_repo_identity=fails(str(repo)+'/.',good))
 moved.rename(repo); flags['retry']=o['load'](str(repo),good,empty) is not None
 try: [o['load'](str(repo),c) for c in [good,missing]]; flags['whole_error']=False
 except o['Failure']: flags['whole_error']=True
 assert all(flags.values())
 cached.append(dict(repo=str(repo),good=good,bad=bad,tree=empty,missing=missing,format=fmt,flags=flags))
print(json.dumps(dict(records=cases,cache=cached)))
"#;
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle required");
    let temp = tempfile::tempdir().unwrap();
    let output = std::process::Command::new("python3")
        .args(["-c", script, &root, temp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases["records"].as_array().unwrap() {
        let tree = case["tree"].as_str();
        let actual = read_statement(
            Path::new(case["repo"].as_str().unwrap()),
            case["commit"].as_str().unwrap(),
            tree,
        );
        if case["oversize"] == true {
            assert!(case["expected"].as_bool().unwrap());
            assert_eq!(actual.unwrap_err().reason, "statement-too-large");
        } else if case["listing_over"] == true {
            assert!(!case["expected"].as_bool().unwrap());
            let error = actual.unwrap_err();
            assert_eq!(error.reason, "error");
            assert!(error.detail.contains("Git output exceeds 1048576 bytes"));
        } else if case["depth"].as_u64().unwrap() > 256 {
            assert!(case["expected"].as_bool().unwrap()); // Python read, not load.
            assert_eq!(actual.unwrap_err().reason, "statement-too-deep");
        } else {
            assert_eq!(
                actual.unwrap().is_some(),
                case["expected"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
    for case in cases["cache"].as_array().unwrap() {
        let repo = Path::new(case["repo"].as_str().unwrap());
        let good = case["good"].as_str().unwrap();
        let bad = case["bad"].as_str().unwrap();
        let tree = case["tree"].as_str().unwrap();
        let missing = case["missing"].as_str().unwrap();
        let mut cache = RecordCache::default();
        let first = cache.load(repo, good, None).unwrap().unwrap();
        let second = cache.load(repo, good, None).unwrap().unwrap();
        let points = |doc: &Document| {
            string(
                field(
                    doc,
                    field(doc, doc.root(), "predicate").unwrap(),
                    "change_id",
                )
                .unwrap(),
            )
            .unwrap()
            .as_ptr()
        };
        let independent = points(&first) != points(&second);
        let wrong = "0".repeat(good.len());
        assert!(cache.load(repo, bad, None).unwrap().is_none());
        assert!(cache.load(repo, good, Some(&wrong)).unwrap().is_none());
        let moved = repo.with_extension("moved");
        std::fs::rename(repo, &moved).unwrap();
        let mut flags = serde_json::json!({
            "independent": independent,
            "positive_hit": cache.load(repo, good, None).unwrap().is_some(),
            "negative_hit": cache.load(repo, bad, None).unwrap().is_none(),
            "tree_hit": cache.load(repo, good, Some(&wrong)).unwrap().is_none(),
            "tree_identity": cache.load(repo, good, Some(tree)).is_err(),
            "commit_identity": cache.load(repo, missing, None).is_err(),
            "repo_identity": cache.load(&moved.join("absent"), good, None).is_err(),
            "lexical_repo_identity": cache.load(&repo.join("."), good, None).is_err(),
        });
        assert_eq!(cache.values.len(), 3); // Errors never become cached refusals.
        std::fs::rename(&moved, repo).unwrap();
        flags["retry"] = serde_json::json!(cache.load(repo, good, Some(tree)).unwrap().is_some());
        let whole = [good, missing]
            .into_iter()
            .map(|id| cache.load(repo, id, None))
            .collect::<Result<Vec<_>, _>>();
        flags["whole_error"] = serde_json::json!(whole.unwrap_err().reason == "error");
        assert_eq!(flags, case["flags"]);
        for (suffix, reason) in [
            ("depth-257", "statement-too-deep"),
            ("cap-over", "statement-too-large"),
        ] {
            let name = format!("{}-{suffix}", case["format"].as_str().unwrap());
            let cap = cases["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
                .unwrap();
            let before = cache.values.len();
            let mixed = [good, cap["commit"].as_str().unwrap()]
                .into_iter()
                .map(|id| cache.load(repo, id, None))
                .collect::<Result<Vec<_>, _>>();
            assert_eq!(mixed.unwrap_err().reason, reason); // No partial successful check.
            assert_eq!(cache.values.len(), before);
        }
    }
    assert_eq!(
        read_statement(temp.path(), "--help", None)
            .unwrap_err()
            .reason,
        "error"
    );
}

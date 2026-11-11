use super::*;
#[test]
fn records_match_python_oracle() {
    let script = r#"
import copy,json,os,pathlib,runpy,subprocess,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
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
 def add(name,value=valid,parents=None,rows=None,path=empty,mode='100644',encoding='utf-8',expected_tree=empty,padding=0,message='record'):
  data=json.dumps(value).encode(encoding) if not isinstance(value,bytes) else value
  data+=b' '*max(0,padding-len(data)); b=blob(data)
  t=tree(rows if rows is not None else [(mode,'blob',b,path)])
  c=commit(t,[subject] if parents is None else parents,message)
  expected=o['read_statement'](str(repo),c,expected_tree) is not None
  cases.append(dict(repo=str(repo),name=fmt+'-'+name,commit=c,tree=expected_tree,expected=expected,oversize=padding>1024*1024))
  return c
 add('valid'); add('unbound',expected_tree=None); add('wrong-request',expected_tree='0'*len(subject))
 add('empty',rows=[]); b=blob(b'x'); add('multiple',rows=[('100644','blob',b,'a'),('100644','blob',b,'b')])
 add('executable',mode='100755'); add('symlink',mode='120000'); add('bad-path',path='not-an-oid')
 add('malformed-json',value=b'{'); add('no-parent',parents=[]); add('wrong-parent',parents=[missing]); add('two-parents',parents=[subject,missing])
 v=copy.deepcopy(valid); v['subject'][0]['name']=missing; add('missing-subject',value=v,parents=[missing])
 v=copy.deepcopy(valid); v['subject'][0]['digest']['gitTree']='0'*len(subject); add('wrong-digest',value=v)
 other=commit(tree([('100644','blob',b,'file')]))
 v=copy.deepcopy(valid); v['subject'][0]['name']=other; add('present-wrong-tree',value=v,parents=[other])
 add('utf16',encoding='utf-16'); add('message-parent',message='parent '+missing)
 c=add('shallow'); (repo/'shallow').write_text(c+'\n')
 add('cap-exact',padding=1024*1024); add('cap-over',padding=1024*1024+1)
print(json.dumps(cases))
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
    for case in cases.as_array().unwrap() {
        let tree = case["tree"].as_str();
        let actual = read_statement(
            Path::new(case["repo"].as_str().unwrap()),
            case["commit"].as_str().unwrap(),
            tree,
        );
        if case["oversize"] == true {
            assert!(case["expected"].as_bool().unwrap());
            assert_eq!(actual.unwrap_err().reason, "statement-too-large");
        } else {
            assert_eq!(
                actual.unwrap().is_some(),
                case["expected"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
    assert_eq!(
        read_statement(temp.path(), "--help", None)
            .unwrap_err()
            .reason,
        "error"
    );
}

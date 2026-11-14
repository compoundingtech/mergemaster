use super::*;
#[test]
fn joined_prefix_preserves_precedence_and_propagates_real_limits() {
    let script = r#"
import ast,json,pathlib,runpy,subprocess,sys
source=pathlib.Path(sys.argv[1]+'/scripts/evidence-verify'); o=runpy.run_path(str(source))
f=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='verified')
f.name='prefix'; f.body=[n for n in f.body if n.lineno<=1008]+[ast.Return(ast.Name('with_check',ast.Load()))]
exec(compile(ast.fix_missing_locations(ast.Module([f],[])),str(source),'exec'),o); cases=[]
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[2])/fmt; root.mkdir(); key=root/'key'
 subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 keys=root/'keys'; keys.write_text('fixture@example.invalid '+key.with_suffix('.pub').read_text())
 names=['trusted','trusted-noise','wrong-check','untrusted','principal','first-untrusted','degraded','degraded-before-wrong','degraded-untrusted','wrong-with-both','degraded-other','stale','no-record','raw-false','scan-size','scan-depth','budget']
 names += [kind+'-'+suffix for suffix in ['surrogate','nonbmp'] for kind in ['trusted','wrong','stale-object','stale-array','stale-string','empty']]
 for name in names:
  check='\ud800' if name.endswith('-surrogate') else '😀' if name.endswith('-nonbmp') else 'check'
  repo=root/name; subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
  def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
  git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
  def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
  def tree(rows=b''): return git('mktree',data=rows).decode().strip()
  current=tree(); subject=git('commit-tree',current,data=b'subject').decode().strip()
  def record(label,tier='full',checks=(check,),signed=True,signer='fixture@example.invalid',layout='tags',wide=False):
   value={'_type':o['STATEMENT_TYPE'],'predicateType':o['PREDICATE_TYPE'],'subject':[{'name':subject,'digest':{'gitTree':current}}],
    'predicate':{'schema_version':1,'change_id':label,'tier':tier,'signer':signer,'observed_at':'2026-01-01T00:00:00Z',
    'observed':{'kind':'tests','runner':'r','checks':{c:{'command':['run'],'exit_code':0,'output_sha256':'0'*64} for c in checks}}}}
   if wide: value['extra']=[0]*500000
   data=json.dumps(value,separators=(',',':')).encode(); assert len(data)<=1048576
   note=tree(('100644 blob '+blob(data)+'\t'+current+'\n').encode())
   args=['-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree',note,'-p',subject]+(['-S'] if signed else [])
   c=git(*args,data=label.encode()).decode().strip(); git('update-ref','refs/'+layout+'/evidence/'+current+'/'+c,c)
  def legacy(data):
   note=tree(('100755 blob '+blob(data)+'\t'+'1'*len(current)+'\n').encode())
   c=git('commit-tree',note,data=b'raw').decode().strip(); git('update-ref','refs/notes/evidence/'+c,c)
  if name in ['trusted','trusted-noise','budget'] or name.startswith('trusted-'): record('good')
  if name in ['wrong-check','degraded-before-wrong','wrong-with-both'] or name.startswith('wrong-'): record('wrong',checks=('other',))
  if name in ['untrusted','trusted-noise','degraded-untrusted','wrong-with-both']: record('unsigned',signed=False)
  if name in ['principal','first-untrusted']: record('principal',signer='other')
  if name=='first-untrusted': record('second',signed=False,layout='notes')
  if name in ['degraded','degraded-before-wrong','degraded-untrusted','wrong-with-both','trusted-noise']: record('degraded',tier='degraded',signed=False)
  if name=='degraded': record('degraded-two',tier='degraded',signed=False,layout='notes')
  if name=='degraded-other': record('degraded-other',tier='degraded',checks=('other',),signed=False)
  raw=b'{"predicate":{"observed":{"checks":"precheckpost"}}}'
  refusal=None
  if name.startswith('stale-'):
   checks={check:0} if name.startswith('stale-object') else [0,check,None] if name.startswith('stale-array') else 'pre'+check+'post'
   legacy(json.dumps({'predicate':{'observed':{'checks':checks}}}).encode())
  elif name in ['stale','degraded-other']: legacy(raw)
  elif name=='raw-false': legacy(b'{"predicate":{"observed":{"checks":[42,null]}}}')
  elif name=='scan-depth':
   legacy(raw[:-1]+b',"extra":'+b'['*256+b'0'+b']'*256+b'}'); refusal='stale-scan-too-deep'
  elif name not in ['no-record','budget'] and not name.startswith('empty-'):
   legacy(raw+b' '*(1048577-len(raw)))
   if name=='scan-size': refusal='stale-scan-too-large'
  if name=='budget':
   for i in range(3): record('wide'+str(i),signed=False,layout='notes',wide=True)
   refusal='record-budget-exceeded'
  try: expected={'records':[c for c,s,p in o['prefix'](str(repo),current,check,str(keys),[])]}
  except o['Failure'] as e: expected={'reason':e.reason,'detail':e.detail,'attempts':e.extra.get('attempts',0)}
  if check!='check':
   if name.startswith('trusted-'): assert len(expected['records'])==1,(name,expected)
   else: assert expected['reason']==('stale_tree' if name.startswith('stale-') else 'wrong_check' if name.startswith('wrong-') else 'no_record'),(name,expected)
   expected.pop('detail',None) # Diagnostic spelling is not this name-identity contract.
   assert o['input_refs'](str(root/'absent'),check,'0'*len(current))==[]
  cases.append(dict(repo=str(repo),tree=current,none='0'*len(current),keys=str(keys),check=list(map(ord,check)),name=fmt+'-'+name,expected=expected,refusal=refusal))
print(json.dumps(cases))
"#;
    let oracle = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new("python3");
    crate::gate::git::sanitize(&mut command);
    let output = command
        .env("HOME", root.path())
        .env("GNUPGHOME", root.path())
        .env("XDG_CONFIG_HOME", root.path())
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
        let mut collector = CandidateCollector::for_check();
        let check: Vec<u32> = serde_json::from_value(f["check"].clone()).unwrap();
        let q = Request {
            repo: Path::new(f["repo"].as_str().unwrap()),
            tree: f["tree"].as_str().unwrap(),
            check: check.as_slice().into(),
            keys: f["keys"].as_str().unwrap(),
            inputs: None,
            crate_key: None,
        };
        if !q.check.text().equals("check") {
            assert!(
                super::super::discovery::input_refs(
                    &root.path().join("absent"),
                    check.as_slice(),
                    q.tree
                )
                .unwrap()
                .is_empty()
            );
        }
        let result = candidates(&mut collector, &q);
        if let Some(reason) = f["refusal"].as_str() {
            assert!(
                matches!(result,Err(e) if e.reason==reason && e.attempts.is_none()),
                "{}",
                f["name"]
            );
            if reason == "record-budget-exceeded" {
                let later = Request {
                    tree: f["none"].as_str().unwrap(),
                    ..q
                };
                assert!(matches!(candidates(&mut collector,&later),Err(e) if e.reason==reason));
                assert!(
                    matches!(candidates(&mut CandidateCollector::for_check(),&later),Err(e) if e.reason=="no_record")
                );
            }
        } else {
            let mut actual = match result {
                Ok(v) => {
                    serde_json::json!({"records":v.iter().map(|c| &c.candidate.commit).collect::<Vec<_>>()})
                }
                Err(e) => {
                    assert_eq!(e.attempts.is_some(), e.reason == "degraded");
                    let mut value = serde_json::to_value(&e).unwrap();
                    // Existing normalized oracle transport only, not CLI field presence.
                    value["attempts"] = e.attempts.unwrap_or(0).into();
                    value
                }
            };
            if !q.check.text().equals("check") {
                actual.as_object_mut().unwrap().remove("detail");
            }
            assert_eq!(actual, f["expected"], "{}", f["name"]);
        }
    }
}
#[test]
fn joined_git_errors_are_not_successful_misses() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    let q = Request {
        repo: &missing,
        tree: &"0".repeat(40),
        check: "check".into(),
        keys: "unused",
        inputs: None,
        crate_key: None,
    };
    let e = candidates(&mut CandidateCollector::for_check(), &q)
        .err()
        .expect("Git error, not candidates");
    assert_eq!(e.reason, "error");
    assert_eq!(e.attempts, None);
}

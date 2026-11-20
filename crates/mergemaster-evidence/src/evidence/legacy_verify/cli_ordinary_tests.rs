#[test]
fn ordinary_paths_match_complete_original_subprocess() {
    let script = r#"
import datetime,hashlib,json,math,os,pathlib,re,runpy,shutil,subprocess,sys
parent=pathlib.Path(sys.argv[1]);rows=[];oracle=parent/'oracle';oracle.mkdir();p=oracle/'evidence-verify'
shutil.copyfile(pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify',p);shutil.copyfile(sys.argv[2],oracle/'rust-test-keys');v=runpy.run_path(str(p))
signer=parent/'signer';subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(signer)],check=True)
keys=parent/('keys'+chr(0xdcff));keys.write_text('agent/fixture '+signer.with_suffix('.pub').read_text());logs=parent/'logs';logs.write_text('log/fixture '+signer.with_suffix('.pub').read_text())
for fmt in ['sha1','sha256']:
 for layout in ['.st','.fractal']:
  repo=parent/(fmt+layout);repo.mkdir()
  def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
  git('init','--object-format='+fmt);git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid');(repo/layout).mkdir();(repo/'def').write_bytes(b'def')
  (repo/'Cargo.toml').write_text('[workspace]\nmembers=["z","a"]')
  for name in ['z','a']:(repo/name).mkdir();(repo/name/'Cargo.toml').write_text('[package]\nname="'+name+'"')
  (repo/layout/'rust-test-inputs.json').write_text('{}');(repo/layout/'evidence-keys').write_bytes(keys.read_bytes());(repo/layout/'evidence-log-key').write_bytes(logs.read_bytes())
  lanes=dict(version=1,lanes={'x':dict(argv=['true'],definition_paths=['def'])});(repo/layout/'required-lanes.json').write_text(json.dumps(lanes))
  def policy(lazy=False):return json.dumps(dict(version=1,checks={'x':dict(trust_levels=['agent'],kinds={'wrapper':dict(command=['true'],base_inputs={'base':'def'},**({'by_level':{'agent':dict(command=['true'],events=['pull_request'],lane=True)}} if lazy else {}))})}))
  policy_file=repo/layout/'evidence-skip-policy.json';policy_file.write_text(policy());git('add','.');git('commit','-m','base');base=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}');lane=v['lane_for'](str(repo),tree,(json.dumps(lanes),base),'x')['sha256']
  members=v['member_keys'](str(repo),tree,base)
  def note(crate=None,key=None):
   inputs={'bound':hashlib.sha256(b'def').hexdigest(),'base':hashlib.sha256(b'def').hexdigest(),'lane_definition_sha256':lane}
   if crate is not None:inputs.update(crate=crate,source_inputs=key,tests_run='1')
   value=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=base,digest=dict(gitTree=tree))],predicate=dict(schema_version=1,tier='full',change_id='fixture',signer='agent/fixture',observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),observed=dict(kind='tests',runner='wrapper',inputs=inputs,checks={'x':dict(command=['true'],exit_code=0,output_sha256='0'*64)})))
   blob=git('hash-object','-w','--stdin',data=json.dumps(value).encode());nt=git('mktree',data=('100644 blob '+blob+'\t'+tree+'\n').encode());commit=git('-c','gpg.format=ssh','-c','user.signingkey='+str(signer),'commit-tree','-S',nt,'-p',base,data=b'note');git('update-ref','refs/tags/evidence/'+tree+'/'+commit,commit)
  for crate,key in members.items():note(crate,key)
  note();empty=git('mktree',data=b'');log=git('-c','gpg.format=ssh','-c','user.signingkey='+str(signer),'commit-tree','-S',empty,data=b'as_of=bad');git('update-ref',v['LOG_REF'],log)
  plain=[[],['--command','["true"]'],['--command','["wrong"]'],['--kinds','nix'],['--trust-levels','host'],['--runner-prefix','wrong'],['--max-age','9'*100],['--bind-input','bound=def'],['--bind-input','missing=def'],['--prefer-levels','host,agent'],['--run-input','bad'],['--log-keys',str(logs)],['--keys-from',base],['--crate-key','bad'],['--members'],['--check','missing']]
  configured=[[],['--members'],['--lanes-from',base],['--run-input','base=caller'],['--log-keys-from',base],['--members','--log-keys',str(logs)],['--lanes-from','missing','--run-input','bad'],['--run-input','bad','--log-keys-from','missing'],['--log-keys-from','missing','--crate-key','bad'],['--crate-key','bad'],['--crate-key','a='+members['a']],['--log-keys',str(keys)],['--lane-base','raw'+chr(0xdcff)],['--check','missing']]
  for lazy in [False,True]:
   policy_file.write_text(policy(lazy));git('add','.');git('commit','--allow-empty','-m','policy');accepted=git('rev-parse','HEAD')
   variants=[([],extra) for extra in plain] if not lazy else []
   variants += [(['--policy-from',accepted,'--repository','org'+chr(0xdcff)],extra) for extra in configured]
   for policy_args,extra in variants:
    key_args=[] if '--keys-from' in extra else ['--keys',str(keys)]
    argv=['--repo',str(repo),'--tree',tree,'--check','x',*key_args,*policy_args,*extra];done=subprocess.run([sys.executable,'-I',str(p),*argv],capture_output=True,env=dict(os.environ,NO_COLOR='1',COLUMNS='80'))
    assert not done.stderr and done.returncode in [0,1],(argv,done.stdout,done.stderr,done.returncode)
    result=json.loads(done.stdout)
    if not extra:assert result['satisfied'],result
    if extra==['--members'] and policy_args:assert result['satisfied'] and result['members']==2,result
    rows.append([[list(os.fsencode(s)) for s in argv],list(done.stdout),list(done.stderr),done.returncode])
  if sys.argv[3]:
   for asof in [datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc),datetime.datetime.now(datetime.timezone.utc)]:
    head=git('-c','gpg.format=ssh','-c','user.signingkey='+str(signer),'commit-tree','-S',empty,data=('as_of='+asof.isoformat()).encode());git('update-ref',v['LOG_REF'],head)
    for extra in [[],['--policy-from',accepted,'--repository','org'],['--policy-from',accepted,'--repository','org','--members']]:
     argv=['--repo',str(repo),'--tree',tree,'--check','x','--keys',str(keys),'--log-keys',str(logs),*extra]
     before=datetime.datetime.now(datetime.timezone.utc)
     expected=subprocess.run([sys.executable,'-I',str(p),*argv],capture_output=True)
     actual=subprocess.run([sys.argv[3],'legacy-evidence-verify',*argv],capture_output=True)
     after=datetime.datetime.now(datetime.timezone.utc)
     for done in [expected,actual]:
      value=json.loads(done.stdout);assert value['satisfied'] and value['log_head']==head,value
      assert math.floor((before-asof).total_seconds()) <= value['log_age_s'] <= math.floor((after-asof).total_seconds()),value
      assert done.stdout.endswith(b'\n')
     def normalize(data):return re.sub(rb'("log_age_s": )-?\d+',rb'\g<1>0',data)
     assert (normalize(actual.stdout),actual.stderr,actual.returncode)==(normalize(expected.stdout),expected.stderr,expected.returncode),(actual,expected)
   git('update-ref',v['LOG_REF'],log)
  for mode in ['ordinary','project','required']:
   for revision in ['-x','--output=f']:
    argv=['--repo',str(repo),'--tree','HEAD','--policy-from='+revision,'--repository','org']+(['--require-all','--keys',str(keys)] if mode=='required' else ['--check','x']+(['--project'] if mode=='project' else ['--keys',str(keys)]))
    detail="--policy-from must not start with '-'";expected=dict(mode='require-all',decision='error',satisfied=False,reason='error',detail=detail) if mode=='required' else dict(satisfied=False,reason='error',check='x',detail=detail)
    rows.append([[list(os.fsencode(s)) for s in argv],list((json.dumps(expected,indent=2)+'\n').encode()),[],2 if mode=='required' else 1])
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .arg(crate::pinned_python::keys_oracle())
        .arg(option_env!("CARGO_BIN_EXE_mergemaster").unwrap_or(""))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<super::super::cli_dispatch::tests::Row> =
        serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.len(), 200);
    super::super::cli_dispatch::tests::compare(rows, "MM_ORDINARY_ONLY");
    for entry in std::fs::read_dir(root.path()).unwrap() {
        assert!(!entry.unwrap().path().join("f").exists());
    }
}

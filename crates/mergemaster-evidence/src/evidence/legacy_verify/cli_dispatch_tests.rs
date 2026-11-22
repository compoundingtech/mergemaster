use std::process::Command;
pub(crate) type Row = (Vec<Vec<u8>>, Vec<u8>, Vec<u8>, i32);
pub(crate) fn compare(rows: Vec<Row>, phase: &str) {
    for (argv, stdout, stderr, code) in rows {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("argv"), serde_json::to_vec(&argv).unwrap()).unwrap();
        let temporary = root.path().join("temporary");
        std::fs::create_dir(&temporary).unwrap();
        let binary = std::env::var_os("CARGO_BIN_EXE_mergemaster");
        let mut command = if let Some(binary) = &binary {
            use std::os::unix::ffi::OsStringExt;
            let mut command = Command::new(binary);
            command
                .arg("legacy-evidence-verify")
                .args(argv.iter().cloned().map(std::ffi::OsString::from_vec));
            command
        } else {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "evidence::legacy_verify::cli_adapter::tests::subprocess_driver",
                    "--nocapture",
                ])
                .env("MM_ADAPTER_DRIVER", root.path())
                .env(phase, "1");
            command
        };
        let done = command
            .env("NO_COLOR", "1")
            .env("COLUMNS", "80")
            .env("TMPDIR", &temporary)
            .output()
            .unwrap();
        assert_eq!(done.status.code(), Some(code), "{argv:?}");
        assert_eq!(
            if binary.is_some() {
                done.stdout
            } else {
                std::fs::read(root.path().join("stdout")).unwrap()
            },
            stdout,
            "{argv:?}"
        );
        assert_eq!(
            if binary.is_some() {
                done.stderr
            } else {
                std::fs::read(root.path().join("stderr")).unwrap()
            },
            stderr,
            "{argv:?}"
        );
        assert_eq!(
            std::fs::read_dir(&temporary).unwrap().count(),
            0,
            "{argv:?}"
        );
    }
}
#[test]
fn tree_resolution_and_outer_handlers_match_original_subprocess() {
    let script = r#"
import json,os,pathlib,subprocess,sys
parent=pathlib.Path(sys.argv[1]); rows=[]
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify'
for fmt in ['sha1','sha256']:
 repo=parent/fmt; repo.mkdir()
 def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
 git('init','--object-format='+fmt); (repo/'a').write_text('a');git('add','.');tree=git('write-tree')
 git('-c','user.name=Fixture','-c','user.email=fixture@example.org','commit','-m','fixture')
 common=['--repo',str(repo),'--project','--check','line\n'+chr(0xdcff)]
 cases=[common+['--tree',tree],common+['--revision','HEAD'],common+['--revision','missing'],common+['--revision','missing'+chr(0xdcff)]]
 cases += [common+['--tree',s] for s in ['HEAD',tree.upper(),tree+'\n',chr(0xdcff),'0'*40,'0'*64]]
 cases += [['--repo',str(repo/'absent'),'--tree','HEAD','--require-all','--policy-from','HEAD','--repository','org','--keys','absent'],['--repo',str(repo/'absent'),'--revision','HEAD','--project','--check','x'],['--tree','HEAD','--project'],['--help']]
 for argv in cases:
  env=dict(os.environ,NO_COLOR='1',COLUMNS='80');env.pop('FORCE_COLOR',None)
  done=subprocess.run([sys.executable,'-I',str(p),*argv],capture_output=True,env=env)
  rows.append([[list(os.fsencode(s)) for s in argv],list(done.stdout),list(done.stderr),done.returncode])
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
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
    let rows: Vec<Row> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 28);
    compare(rows, "MM_TREE_ONLY");
}

#[test]
fn complete_project_paths_match_original_subprocess() {
    let script = r#"
import json,os,pathlib,shutil,subprocess,sys
parent=pathlib.Path(sys.argv[1]); rows=[]
oracle=parent/'oracle';oracle.mkdir();p=oracle/'evidence-verify'
shutil.copyfile(pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify',p)
shutil.copyfile(sys.argv[2],oracle/'rust-test-keys')
for fmt in ['sha1','sha256']:
 for layout in ['.st','.fractal']:
  repo=parent/(fmt+layout);repo.mkdir()
  def git(*args):return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
  git('init','--object-format='+fmt);(repo/layout).mkdir()
  (repo/'Cargo.toml').write_text('[workspace]\nmembers=["z","a"]')
  for name in ['z','a']:
   (repo/name).mkdir();(repo/name/'Cargo.toml').write_text('[package]\nname="'+name+'"')
  (repo/layout/'rust-test-inputs.json').write_text('{}')
  policy=dict(version=1,checks={'x':dict(trust_levels=['agent'],inputs=['a/Cargo.toml'],kinds=dict(wrapper=dict(command=['{repository}'],base_inputs={'base':'a/Cargo.toml','missing':'absent'})))})
  (repo/layout/'evidence-skip-policy.json').write_text(json.dumps(policy))
  git('add','.');git('-c','user.name=Fixture','-c','user.email=fixture@example.org','commit','-m','fixture');tree=git('rev-parse','HEAD^{tree}')
  plain=['--repo',str(repo),'--revision','HEAD','--check','x','--project']
  policy_args=['--policy-from','HEAD','--repository','org/'+chr(0xdcff)]
  variants=[[],['--paths','z/Cargo.toml,a/Cargo.toml,z/Cargo.toml'],['--paths','..'],['--paths',''],policy_args,policy_args+['--paths','z/Cargo.toml'],policy_args+['--paths','.'],policy_args+['--members'],['--members'],['--members','--policy-from','','--repository','org'],['--keys-from','missing','--log-keys-from','missing','--run-input','bad','--lanes-from','missing','--crate-key','bad'],policy_args+['--check','absent'],['--check','raw'+chr(0xdcff)]]
  for extra in variants:
   argv=plain+extra;env=dict(os.environ,NO_COLOR='1',COLUMNS='80');env.pop('FORCE_COLOR',None)
   done=subprocess.run([sys.executable,'-I',str(p),*argv],capture_output=True,env=env)
   result=json.loads(done.stdout);assert done.returncode in [0,1] and not done.stderr
   if extra==policy_args:assert result['base_inputs']['missing']=='absent' and result['source_inputs']
   if extra==policy_args+['--members']:assert list(result['crates'])==['a','z']
   rows.append([[list(os.fsencode(s)) for s in argv],list(done.stdout),list(done.stderr),done.returncode])
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .arg(crate::pinned_python::keys_oracle())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<Row> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 52);
    compare(rows, "MM_PROJECT_ONLY");
}

#[test]
fn complete_required_path_and_signer_cleanup_match_original_subprocess() {
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
parent=pathlib.Path(sys.argv[1]);rows=[];temporary=parent/'temporary';temporary.mkdir()
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify';v=runpy.run_path(str(p))
key=parent/'signer';subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
keys=parent/('allowed-'+chr(0xdcff));keys.write_text('agent/fixture '+key.with_suffix('.pub').read_text())
for fmt in ['sha1','sha256']:
 for layout in ['.st','.fractal']:
  repo=parent/(fmt+layout);repo.mkdir()
  def git(*args,data=None):return subprocess.check_output(['git','-C',str(repo),*args],input=data,stderr=subprocess.PIPE).decode().strip()
  git('init','--object-format='+fmt);git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
  (repo/layout).mkdir();(repo/'def').write_text('definition')
  (repo/layout/'evidence-keys').write_bytes(keys.read_bytes())
  lanes=dict(version=1,lanes={'x':dict(argv=['true'],definition_paths=['def'])})
  (repo/layout/'required-lanes.json').write_text(json.dumps(lanes))
  def policy(mode='reject',check='x'):return json.dumps(dict(version=1,checks={check:dict(require=mode,trust_levels=['agent'],kinds={'wrapper':dict(command=['true'])})}))
  policy_file=repo/layout/'evidence-skip-policy.json';policy_file.write_text(policy())
  git('add','.');git('commit','-m','base');base=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
  inputs={'lane_definition_sha256':v['lane_for'](str(repo),tree,(json.dumps(lanes),base),'x')['sha256']}
  statement=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=base,digest=dict(gitTree=tree))],predicate=dict(schema_version=1,tier='full',change_id='fixture',signer='agent/fixture',observed_at='2026-01-01T00:00:00Z',observed=dict(kind='tests',runner='wrapper',inputs=inputs,checks={'x':dict(command=['true'],exit_code=0,output_sha256='0'*64)})))
  blob=git('hash-object','-w','--stdin',data=json.dumps(statement).encode())
  note=git('mktree',data=('100644 blob '+blob+'\t'+tree+'\n').encode())
  commit=git('-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',note,'-p',base,data=b'fixture')
  git('update-ref','refs/tags/evidence/'+tree+'/'+commit,commit)
  variants=[(policy(),[], 'ok'),(policy(),['--lanes-from','HEAD'],'ok'),(policy(),['--keys-from','HEAD'],'ok'),(policy(),['--run-input','bad','--log-keys-from','missing','--crate-key','bad'],'ok'),(policy('off'),[],'ok'),(policy('reject','y'),[],'reject'),(policy('shadow','y'),[],'would-reject'),(policy(),['--lanes-from','missing'],'error'),(policy(),['--lanes-from','HEAD','--lane-base','raw'+chr(0xdcff)],'error'),('not JSON',[],'error'),('\ufeff'+policy(),[],'error'),(policy(),['--keys',str(parent/'missing')],'error'),(policy(),['--keys-from','missing'],'error')]
  variants += [('not JSON',['--keys-from','HEAD'],'error'),(policy(),['--keys-from','HEAD','--lanes-from','missing'],'error')]
  for index,(text,extra,decision) in enumerate(variants):
   policy_file.write_text(text);git('add','.');git('commit','--allow-empty','-m',str(index))
   accepted=git('rev-parse','HEAD');extra=[accepted if s=='HEAD' else s for s in extra]
   key_args=[] if '--keys' in extra or '--keys-from' in extra else ['--keys',str(keys)]
   argv=['--repo',str(repo),'--tree',tree,'--require-all','--policy-from',accepted,'--repository','org/'+chr(0xdcff),*key_args,*extra]
   env=dict(os.environ,NO_COLOR='1',COLUMNS='80',TMPDIR=str(temporary));env.pop('FORCE_COLOR',None)
   done=subprocess.run([sys.executable,'-I',str(p),*argv],capture_output=True,env=env)
   result=json.loads(done.stdout);assert result['decision']==decision,(argv,result)
   assert done.returncode==({'reject':1,'error':2}.get(decision,0)) and not done.stderr
   if decision=='ok' and index<4:assert result['lanes']['x']['record']==commit
   assert not list(temporary.iterdir())
   rows.append([[list(os.fsencode(s)) for s in argv],list(done.stdout),list(done.stderr),done.returncode])
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
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
    let rows: Vec<Row> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 60);
    compare(rows, "MM_REQUIRED_ONLY");
}

#[test]
fn parser_preflight_and_ci_inputs_routes_fail_closed_like_oracle() {
    let script = r#"
import json,os,pathlib,subprocess,sys
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify';rows=[]
base=['--tree','a'*40,'--project','--check','x']
helpers=['--ci-inputs-unchanged','--unresolved-ci-inputs','--ci_inputs_unchanged','--unresolved_ci_inputs','ci_inputs_unchanged','unresolved_ci_inputs']
cases=[base+[name] for name in helpers]
cases += [[],['--help'],['--tree'],['--tr'],base+['--unknown'],base+['--max-age','no'],base+['--revision','HEAD'],['--tree','a'*40],base+['--command','[1]'],base+['--bind-input','bad']]
for argv in cases:
 done=subprocess.run([sys.executable,'-I',str(p),*argv],capture_output=True,env=dict(os.environ,NO_COLOR='1',COLUMNS='80'))
 if argv and argv[-1] in helpers: assert done.returncode==2 and not done.stdout
 rows.append([[list(os.fsencode(s)) for s in argv],list(done.stdout),list(done.stderr),done.returncode])
print(json.dumps(rows))
"#;
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<Row> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.len(), 16);
    compare(rows, "MM_TREE_ONLY");
}

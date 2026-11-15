use std::process::Command;
pub(super) type Row = (Vec<Vec<u8>>, Vec<u8>, Vec<u8>, i32);
pub(super) fn compare(rows: Vec<Row>, phase: &str) {
    for (argv, stdout, stderr, code) in rows {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("argv"), serde_json::to_vec(&argv).unwrap()).unwrap();
        let done = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "evidence::legacy_verify::cli_adapter::tests::subprocess_driver",
                "--nocapture",
            ])
            .env("MM_ADAPTER_DRIVER", root.path())
            .env(phase, "1")
            .env("NO_COLOR", "1")
            .env("COLUMNS", "80")
            .output()
            .unwrap();
        assert_eq!(done.status.code(), Some(code), "{argv:?}");
        assert_eq!(
            std::fs::read(root.path().join("stdout")).unwrap(),
            stdout,
            "{argv:?}"
        );
        assert_eq!(
            std::fs::read(root.path().join("stderr")).unwrap(),
            stderr,
            "{argv:?}"
        );
    }
}
#[test]
fn tree_resolution_and_outer_handlers_match_original_subprocess() {
    let script = r#"
import json,os,pathlib,subprocess,sys
parent=pathlib.Path(sys.argv[1]); rows=[]
child=r'''import ast,json,os,pathlib,runpy,sys
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify'
v=runpy.run_path(str(p)); module=ast.parse(p.read_text()); f=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
t=next(n for n in f.body if isinstance(n,ast.Try) and any(isinstance(x,ast.Assign) and ast.unparse(x.targets[0])=='tree' for x in n.body))
i=next(i for i,n in enumerate(t.body) if isinstance(n,ast.If) and ast.unparse(n.test)=='args.project and args.members')
t.body=t.body[:i]+ast.parse("print(json.dumps({'tree':tree},indent=2))\nreturn 0").body
exec(compile(ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[])),str(p),'exec'),v)
sys.argv[0]='evidence-verify'; sys.exit(v['main'](sys.argv[1:]))
'''
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
  done=subprocess.run([sys.executable,'-I','-c',child,*argv],capture_output=True,env=env)
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
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/fractal/scripts/rust-test-keys"),
        )
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

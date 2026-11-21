use super::{discovery, divergence_witnesses::capture, lane_git, projection};
use crate::evidence::legacy_policy::PolicyError;
use serde_json::{Value, json};
use std::path::Path;

fn observed<T: serde::Serialize>(result: Result<T, PolicyError>) -> Value {
    match result {
        Ok(value) => json!({"result":value}),
        Err(error) => {
            json!({"error":{"reason":error.reason,"detail":error.detail.to_string(),"origin":format!("{:?}",error.origin)}})
        }
    }
}

#[test]
fn transport_divergence_witnesses() {
    const CHILD: &str = "MERGEMASTER_TRANSPORT_WITNESS_CHILD";
    if let Ok(raw) = std::env::var(CHILD) {
        let case: Value = serde_json::from_str(&raw).unwrap();
        let id = case["id"].as_str().unwrap();
        let repo = Path::new(".");
        let tree = case["tree"].as_str().unwrap();
        let rust = match id {
            "tree-ref-oid-layout" => observed(discovery::tree_refs(repo, tree)),
            "discovery-ref-prefix" => observed(discovery::records_under(repo, &["bad/".into()])),
            "discovery-commit-oid"
            | "discovery-note-lf"
            | "discovery-note-cr"
            | "discovery-note-nul"
            | "discovery-batch-frame" => {
                let commits: Vec<String> = serde_json::from_value(case["commits"].clone()).unwrap();
                observed(discovery::with_note_for(repo, &commits, tree))
            }
            "lane-config-revision-oid" => observed(lane_git::read_lanes(repo, "HEAD")),
            "projection-tree-oid" => observed(projection::project(repo, tree, &[".".into()])),
            "projection-output-cap" | "projection-output-shape" => {
                observed(projection::project(repo, tree, &["file".into()]))
            }
            _ => panic!("unknown witness {id}"),
        };
        assert!(rust["error"].is_object(), "{id}: {rust}");
        capture(id, case["input"].clone(), case["python"].clone(), rust);
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let output = crate::pinned_python::command().args(["-c", r#"
import json,os,pathlib,runpy,sys
root=pathlib.Path(sys.argv[1]);o=runpy.run_path(os.environ['MERGEMASTER_PYTHON_ORACLE']+'/scripts/evidence-verify')
shim=root/'git'
shim.write_text('#!'+sys.executable+'''\nimport os,sys
args=sys.argv[1:];oid='b'*40
if 'check-ref-format' in args: pass
elif 'for-each-ref' in args:
 prefix=args[-1].rstrip('/')+'/'
 print(oid+' '+prefix+oid)
elif 'cat-file' in args and '--batch-check' in args:
 for q in sys.stdin.buffer: print('broken' if os.environ['MM_TRANSPORT_ID']=='discovery-batch-frame' else oid+' blob 0',flush=True)
elif 'ls-tree' in args:
 if os.environ['MM_TRANSPORT_ID']=='lane-config-revision-oid': sys.stdout.buffer.write(('100644 blob '+oid+'\\t.st/required-lanes.json\\0').encode())
 else: sys.stdout.buffer.write(('100644 blob '+oid+'\\tfile\\0').encode())
elif 'show' in args: print('{}')
elif 'update-index' in args: sys.stdin.buffer.read()
elif 'write-tree' in args: print('a'*66 if os.environ['MM_TRANSPORT_ID']=='projection-output-cap' else 'not-an-object-id')
else: raise SystemExit('unexpected Git operation '+repr(args))
''');shim.chmod(0o700)
os.environ['PATH']=str(root)
cases=[]
for id in ['tree-ref-oid-layout','discovery-ref-prefix','discovery-commit-oid','discovery-note-lf','discovery-note-cr','discovery-note-nul','discovery-batch-frame','lane-config-revision-oid','projection-tree-oid','projection-output-cap','projection-output-shape']:
 os.environ['MM_TRANSPORT_ID']=id
 tree='a'*40; commits=['c'*40]
 if id in ['tree-ref-oid-layout','projection-tree-oid']: tree='HEAD'
 if id=='discovery-commit-oid': commits=['HEAD']
 if id.startswith('discovery-note-'): tree={'discovery-note-lf':'note\npath','discovery-note-cr':'note\rpath','discovery-note-nul':'note\0path'}[id]
 try:
  if id=='tree-ref-oid-layout': result=o['tree_refs']('.',tree)
  elif id=='discovery-ref-prefix': result=o['records_under']('.',['bad/'])
  elif id.startswith('discovery-'): result=o['with_note_for']('.',commits,tree)
  elif id=='lane-config-revision-oid': result=o['read_lanes']('.','HEAD')
  else: result=o['project']('.',tree,['.'] if id=='projection-tree-oid' else ['file'])
  python=dict(result=result)
 except Exception as error:
  python=dict(error=dict(reason=getattr(error,'reason',None),detail=str(error),origin=type(error).__name__))
 cases.append(dict(id=id,tree=tree,commits=commits,python=python,input=dict(tree=tree,commits=commits,prefix='bad/' if id=='discovery-ref-prefix' else None,transport='scripted Git protocol',write_tree_stdout='a'*66+'\n' if id=='projection-output-cap' else 'not-an-object-id\n' if id=='projection-output-shape' else None)))
print(json.dumps(cases))
"#]).arg(directory.path()).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "evidence::legacy_verify::transport_witness_tests::transport_divergence_witnesses",
                "--nocapture",
            ])
            .env(CHILD, case.to_string())
            .env("MM_TRANSPORT_ID", case["id"].as_str().unwrap())
            .env("PATH", directory.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn signed_tree_local_patch_preserves_binary_transport_bytes() {
    let scratch = tempfile::tempdir().unwrap();
    let local = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let output = crate::pinned_python::command().args(["-c", r#"
import json,os,pathlib,runpy,subprocess,sys
consumer=pathlib.Path(sys.argv[1]);(consumer/'scripts').mkdir()
(consumer/'scripts/evidence-verify').write_text("print('consumer-verifier-decoy')\n")
os.chdir(consumer)
binary=sys.argv[4]
if not binary:
 # Unit targets use the same real Rust adapter subprocess driver as cli_dispatch_tests.
 driver=consumer/'adapter'
 driver.write_text('#!'+sys.executable+'\n'+'''
import json,os,pathlib,subprocess,sys,tempfile
assert sys.argv.pop(1)=='legacy-evidence-verify'
with tempfile.TemporaryDirectory() as directory:
 root=pathlib.Path(directory)
 (root/'argv').write_text(json.dumps([list(os.fsencode(arg)) for arg in sys.argv[1:]]))
 done=subprocess.run([sys.argv[0]+'.test','--exact','evidence::legacy_verify::cli_adapter::tests::subprocess_driver','--nocapture'],
                     env=dict(os.environ,MM_ADAPTER_DRIVER=directory),stdout=subprocess.DEVNULL)
 sys.stdout.buffer.write((root/'stdout').read_bytes())
 sys.stderr.buffer.write((root/'stderr').read_bytes())
 sys.exit(done.returncode)
''')
 driver.chmod(0o700)
 (consumer/'adapter.test').symlink_to(sys.argv[3])
 binary=str(driver)
os.environ['MERGEMASTER_BIN']=binary
os.environ['NO_COLOR']='1'
os.environ['COLUMNS']='80'
module=runpy.run_path(str(pathlib.Path(sys.argv[2])/'scripts/ci-signed-tree'))
assert module['VERIFIER']==binary
observations=[]
for argv in [['--help'],[os.fsdecode(b'--unknown-\xff')]]:
 command=[binary,'legacy-evidence-verify',*argv]
 direct=subprocess.run(command,capture_output=True)
 launched=[]
 original_run=subprocess.run
 def record_launch(actual,*args,**kwargs):
  launched.append([os.fsencode(arg) for arg in actual])
  return original_run(actual,*args,**kwargs)
 subprocess.run=record_launch
 try:
  transported=module['run_err'](*command)
 finally:
  subprocess.run=original_run
 assert launched==[[os.fsencode(arg) for arg in command]],(command,launched)
 assert transported==(direct.returncode,direct.stdout,direct.stderr),(argv,transported,direct)
 assert direct.returncode==(0 if argv==['--help'] else 2),direct
 observations.append(dict(argv=[list(os.fsencode(arg)) for arg in argv],
                          launched_argv=[[list(arg) for arg in actual] for actual in launched],
                          exit=transported[0],stdout=list(transported[1]),stderr=list(transported[2])))
upstream=runpy.run_path(str(pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/ci-signed-tree'))
previous=upstream['run_err'](sys.executable,upstream['VERIFIER'],'--help')
assert previous[0]==0,previous
print(json.dumps(dict(upstream=dict(exit=previous[0],stdout=list(previous[1]),stderr=list(previous[2])),
                      binary=observations)))
"#]).arg(scratch.path()).arg(local).arg(std::env::current_exe().unwrap())
        .arg(option_env!("CARGO_BIN_EXE_mergemaster").unwrap_or("")).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observations: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observations["binary"].as_array().unwrap().len(), 2);
    assert_eq!(observations["binary"][0]["exit"], 0);
    assert_eq!(observations["binary"][1]["exit"], 2);
    super::divergence_witnesses::capture_python_patch(
        "ci-signed-tree-sibling-verifier",
        json!({"consumer_verifier":"print('consumer-verifier-decoy')","invocation":["VERIFIER","legacy-evidence-verify"],"boundary":"ci-signed-tree run_err preserves binary exit/stdout/stderr bytes"}),
        observations["upstream"].clone(),
        observations["binary"].clone(),
    );
}

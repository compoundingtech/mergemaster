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
fn signed_tree_local_patch_uses_the_adjacent_python_verifier() {
    let scratch = tempfile::tempdir().unwrap();
    let local = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let output = crate::pinned_python::command().args(["-c", r#"
import json,os,pathlib,runpy,sys
consumer=pathlib.Path(sys.argv[1]);(consumer/'scripts').mkdir()
(consumer/'scripts/evidence-verify').write_text("print('consumer-verifier-decoy')\n")
os.chdir(consumer)
observations=[]
for label,root in [('upstream-python',os.environ['MERGEMASTER_PYTHON_ORACLE']),('local-python-patch',sys.argv[2])]:
 module=runpy.run_path(str(pathlib.Path(root)/'scripts/ci-signed-tree'))
 verifier=module['VERIFIER']
 result=module['run'](sys.executable,verifier,'--help')
 observations.append(dict(implementation=label,verifier=verifier,api_result=[list(v) if isinstance(v,bytes) else v for v in result]))
print(json.dumps(observations))
"#]).arg(scratch.path()).arg(local).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observations: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observations[1]["api_result"][0], 0);
    super::divergence_witnesses::capture_python_patch(
        "ci-signed-tree-sibling-verifier",
        json!({"consumer_verifier":"print('consumer-verifier-decoy')","invocation":["python","VERIFIER","--help"],"boundary":"ci-signed-tree VERIFIER selection and run API"}),
        observations[0].clone(),
        observations[1].clone(),
    );
}

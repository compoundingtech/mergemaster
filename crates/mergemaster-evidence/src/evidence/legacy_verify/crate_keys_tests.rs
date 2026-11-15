use super::*;
use serde_json::{Value, json};
#[test]
fn keys_and_json_cli_match_pinned_oracle() {
    let script = r#"
import json,pathlib,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
repo=pathlib.Path(sys.argv[2]); tool=pathlib.Path(sys.argv[1]); verifier=pathlib.Path(sys.argv[3])/'scripts/evidence-verify'
def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
git('init')
def write(name,text):
 p=repo/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(text)
write('Cargo.toml','[workspace]\nmembers=["z","a"]')
write('z/Cargo.toml','[package]\nname="z"\n[dependencies]\na={path="../a"}')
write('a/Cargo.toml','[package]\nname="a"')
write('z/src/lib.rs','pub fn z() {}')
write('a/src/lib.rs','pub fn a() {}')
write('.st/rust-test-inputs.json',json.dumps({'global':['Cargo.toml'],'crates':{'z':{'extra':[]},'a':{'extra':['absent']}}}))
git('add','.'); base=git('write-tree')
write('.fractal/rust-test-inputs.json',json.dumps({'global':[],'crates':{}}))
write('a/src/lib.rs','pub fn a() { /* candidate */ }')
git('add','.'); tree=git('write-tree'); cases=[]
for revision,inputs,names in [(tree,None,[]),(tree,base,[]),(tree,base,['z']),(tree,base,['a','z','a']),(tree,base,['missing','z','other','missing']),('missing-tree','missing-inputs',[]),(tree,'missing-inputs',['unknown'])]:
 for paths in [False,True]:
  args=[sys.executable,str(tool),'--repo',str(repo),'--tree',revision,'--verifier',str(verifier),'--json']
  if inputs is not None: args+=['--inputs-from',inputs]
  for name in names: args+=['--crate',name]
  if paths: args+=['--paths']
  done=subprocess.run(args,capture_output=True,text=True)
  cases.append(dict(tree=revision,inputs=inputs,names=names,paths=paths,status=done.returncode,stderr=done.stderr,result=json.loads(done.stdout) if done.returncode==0 else None))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let tool = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/fractal/scripts/rust-test-keys");
    let out = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(tool)
        .arg(repo.path())
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    for case in &cases {
        let source = TreeSource {
            repo: repo.path(),
            tree: case["tree"].as_str().unwrap(),
            no_lazy_fetch: true,
        };
        let names: Vec<String> = serde_json::from_value(case["names"].clone()).unwrap();
        match source.keys_from(case["inputs"].as_str(), &names) {
            Ok(keys) => {
                assert_eq!(case["status"], 0, "{case}");
                assert_eq!(case["stderr"], "");
                let result: serde_json::Map<_, _> = keys
                    .into_iter()
                    .map(|(name, value)| {
                        let paths: Vec<_> = value.paths.iter().map(ToString::to_string).collect();
                        let value = if case["paths"] == true {
                            json!({"key":value.key,"paths":paths})
                        } else {
                            json!(value.key)
                        };
                        (name, value)
                    })
                    .collect();
                assert_eq!(json!(result), case["result"], "{case}");
            }
            Err(error) => {
                assert_eq!(
                    error.origin,
                    crate::evidence::legacy_policy::ErrorOrigin::Failure
                );
                assert_eq!(error.reason, "error");
                assert_eq!(case["status"], 2);
                assert_eq!(
                    format!("rust-test-keys: {}\n", error.detail),
                    case["stderr"].as_str().unwrap(),
                    "{case}"
                );
            }
        }
    }
    assert_eq!(cases.len(), 14);
}

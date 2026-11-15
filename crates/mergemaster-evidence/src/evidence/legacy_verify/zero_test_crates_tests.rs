use super::*;
use serde_json::{Value, json};
#[test]
fn standalone_allowance_matches_python_without_read_inputs_schema() {
    let script = r#"
import ast,json,pathlib,subprocess,sys,os
assert sys.version_info[:3]==(3,14,7)
class Failure(Exception):
 def __init__(self,reason,detail): self.reason=reason; super().__init__(detail)
module=ast.parse(pathlib.Path(sys.argv[1]).read_text())
names={'git','config_path','zero_test_crates'}
exec(compile(ast.Module(body=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[]),'oracle','exec'))
repo=pathlib.Path(sys.argv[2])
def run(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
run('init')
samples=['{}','{"no_tests":[]}','{"no_tests":["x","x","é","\\ud800","\\udcff","😀",""]}','{"global":false,"crates":0,"no_tests":["x"]}','[]','null','true','123','"x"','1e999','NaN','{"no_tests":null}','{"no_tests":false}','{"no_tests":"x"}','{"no_tests":{}}','{"no_tests":[1]}','{"no_tests":[true]}','{"no_tests":[null]}','{"no_tests":[[]]}','{"no_tests":[{}]}','','[1,]','\ufeff{}','9'*4301,'{"ignored":'+'9'*4301+'}','{"no_tests":null,"no_tests":[]}','{"no_tests":[],"no_tests":null}']
fixtures=[(s.encode(),None) for s in samples]+[(b'\xff',None),('{}'.encode('utf-16'),None),(None,None),(b'{}',b'{'),(b'{',b'{}'),(b'{}',b'\xff'),(b'{',b'DIRECTORY')]
for i,(old,new) in enumerate(fixtures):
 base=repo/str(i); base.mkdir(); (base/'marker').touch()
 for name,data in [('.st/rust-test-inputs.json',old),('.fractal/rust-test-inputs.json',new)]:
  if data is None: continue
  p=base/name; p.parent.mkdir(parents=True,exist_ok=True)
  if data==b'DIRECTORY': p.mkdir(); (p/'child').touch()
  else: p.write_bytes(data)
run('add','.'); tree=run('write-tree'); cases=[]
for i in range(len(fixtures)):
 base=run('rev-parse',f'{tree}:{i}')
 try: expected={'ok':sorted([[ord(c) for c in s] for s in zero_test_crates(repo,base)])}
 except Failure as e: expected={'reason':e.reason,'class':'Failure','detail':str(e)}
 except Exception as e: expected={'class':type(e).__name__,'detail':str(e)}
 cases.append(dict(base=base,expected=expected))
subtree=run('rev-parse',f'{tree}:2')
raw=f'tree {subtree}\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nallowance\n'.encode()
commit=subprocess.check_output(['git','-C',str(repo),'hash-object','-t','commit','-w','--stdin'],input=raw).decode().strip()
run('update-ref','refs/heads/allowance',commit); run('symbolic-ref','HEAD','refs/heads/allowance')
for base in ['HEAD','allowance',commit[:12],'unknown-revision']:
 try: expected={'ok':sorted([[ord(c) for c in s] for s in zero_test_crates(repo,base)])}
 except Failure as e: expected={'reason':e.reason,'class':'Failure','detail':str(e)}
 except Exception as e: expected={'class':type(e).__name__,'detail':str(e)}
 cases.append(dict(base=base,expected=expected))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let oracle = std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .join("scripts/evidence-verify");
    let out = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(oracle)
        .arg(repo.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    for case in &cases {
        let actual = match zero_test_crates(repo.path(), case["base"].as_str().unwrap()) {
            Ok(names) => json!({"ok":names}),
            Err(e) => {
                use crate::evidence::legacy_policy::ErrorOrigin;
                let class = match e.origin {
                    ErrorOrigin::Failure => "Failure",
                    ErrorOrigin::Exception { class } => class,
                };
                if class == "Failure" {
                    json!({"reason":e.reason,"class":class,"detail":e.detail.to_string()})
                } else {
                    json!({"class":class,"detail":e.detail.to_string()})
                }
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 38);
}

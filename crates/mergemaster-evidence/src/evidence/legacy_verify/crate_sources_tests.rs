use super::*;
use serde_json::{Value, json};
#[test]
fn accepted_sources_match_oracle_before_tool_execution() {
    let script = r#"
import ast,json,os,pathlib,subprocess,sys
from pathlib import Path
assert sys.version_info[:3]==(3,14,7)
repo=Path(sys.argv[2]); os.chdir(repo)
class Failure(Exception): pass
module=ast.parse(Path(sys.argv[1]).read_text()); names={'git','config_path','config_blob','crate_keys'}
selected=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name in names]
for node in selected:
 if node.name=='crate_keys':
  # Observe real selection after verifier.write_bytes, before subprocess.run.
  stop=next(i for i,n in enumerate(node.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='done' for t in n.targets))
  node.body=node.body[:stop]+ast.parse("return {'tool':list(tool.read_bytes()),'verifier':list(verifier.read_bytes()),'inputs_from':inputs_at}").body
exec(compile(ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[])),'oracle','exec'))
RUST_TEST_KEYS='scripts/rust-test-keys'; RUST_TEST_INPUTS='rust-test-inputs.json'
def run(*args): return subprocess.check_output(['git',*args],stderr=subprocess.PIPE).decode().strip()
run('init')
def write(base,path,data):
 if data is None: return
 p=base/path; p.parent.mkdir(parents=True,exist_ok=True)
 if data==b'DIRECTORY': p.mkdir(); (p/'child').write_bytes(b'child')
 else: p.write_bytes(data)
fixtures=[]
for tool in [None,b'base-tool',b'DIRECTORY']:
 for old,new in [(None,None),(b'{}',None),(b'{',None),(b'{}',b'{'),(b'{',b'{}'),(b'{}',b'\xef\xbb\xbf{}'),(None,'{}'.encode('utf-16')),(None,b'\xff'),(None,b'DIRECTORY'),(None,b'9'*4301)]:
  for judged in [False,True]: fixtures.append((tool,old,new,judged,b'candidate-tool',True))
fixtures += [(None,None,None,False,None,True),(None,None,None,False,b'DIRECTORY',True),(b'base-tool',b'{}',None,False,b'candidate-tool',False)]
for i,(tool,old,new,judged,candidate,verifier) in enumerate(fixtures):
 base=repo/str(i)/'base'; base.mkdir(parents=True)
 write(base,RUST_TEST_KEYS,tool); write(base,'.st/'+RUST_TEST_INPUTS,old); write(base,'.fractal/'+RUST_TEST_INPUTS,new)
 write(base,'scripts/evidence-verify',b'base-verifier' if verifier else None)
 write(base,'marker',b'x'); write(repo/str(i)/'candidate',RUST_TEST_KEYS,candidate)
run('add','.'); tree=run('write-tree'); cases=[]
for i,(_,_,_,judged,_,_) in enumerate(fixtures):
 base=run('rev-parse',f'{tree}:{i}/base'); candidate=repo/str(i)/'candidate'; scratch=repo/str(i)/'scratch'; scratch.mkdir()
 calls=[]
 def judged_by_policy(base): calls.append(base); return judged
 try:
  result=crate_keys(base,candidate,'candidate-tree',scratch)
  expected={'class':'Failure','detail':result[1]} if isinstance(result,tuple) else {'ok':result}
 except Exception as e: expected={'class':type(e).__name__,'detail':str(e)}
 cases.append(dict(base=base,candidate=str(candidate),judged=judged,calls=len(calls),expected=expected))
base='invalid-base'; calls=[]
try: crate_keys(base,candidate,'candidate-tree',scratch)
except Exception as e: expected={'class':type(e).__name__,'detail':str(e)}
else: raise AssertionError('invalid base accepted')
cases.append(dict(base=base,candidate=str(candidate),judged=judged,calls=len(calls),expected=expected))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let script_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/st-test");
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .arg(script_path)
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
        let source = AcceptedSource {
            repo: repo.path(),
            base: case["base"].as_str().unwrap(),
        };
        let mut calls = 0;
        let actual = match source.resolve(
            Path::new(case["candidate"].as_str().unwrap()),
            "candidate-tree",
            || {
                calls += 1;
                Ok(case["judged"].as_bool().unwrap())
            },
        ) {
            Ok(selected) => {
                json!({"ok":{"tool":selected.tool,"verifier":selected.verifier,"inputs_from":selected.inputs_from}})
            }
            Err(error) => {
                let class = match error.origin {
                    crate::evidence::legacy_policy::ErrorOrigin::Failure => "Failure",
                    crate::evidence::legacy_policy::ErrorOrigin::Exception { class } => class,
                };
                assert_eq!(error.reason, "error");
                json!({"class":class,"detail":error.detail.to_string()})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
        assert_eq!(json!(calls), case["calls"]);
    }
    assert_eq!(cases.len(), 64);
}
#[test]
fn checked_git_stderr_matches_python_replacement_strip_and_codepoint_suffix() {
    let script = r#"
import json
samples=[b'\x1c\xff\xed\xa0\x80\xf0\x9f\x1f', ('\u2003'+('é🦀'*250)+'\x1c').encode(), b'\xef\xbb\xbf\0\n']
print(json.dumps([[list(b),'git show failed: '+b.decode(errors='replace').strip()[-400:]] for b in samples]))
"#;
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(out.status.success());
    let cases: Vec<(Vec<u8>, String)> = serde_json::from_slice(&out.stdout).unwrap();
    for (bytes, expected) in cases {
        assert_eq!(git_failure("show", &bytes).detail.to_string(), expected);
    }
}

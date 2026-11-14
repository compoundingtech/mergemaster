use super::*;
use serde_json::{Value as Json, json};
fn kind(node: &Node) -> &'static str {
    match node {
        Node::Null => "NoneType",
        Node::Bool(_) => "bool",
        Node::Integer(_) => "int",
        Node::Float(_) => "float",
        Node::String(_) => "str",
        Node::Array(_) => "list",
        Node::Object(_) => "dict",
    }
}
#[test]
fn input_documents_match_oracle_and_never_downgrade() {
    let script = r#"
import importlib.machinery,importlib.util,json,pathlib,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
l=importlib.machinery.SourceFileLoader('keys',sys.argv[1]); spec=importlib.util.spec_from_loader('keys',l); m=importlib.util.module_from_spec(spec); l.exec_module(m)
repo=pathlib.Path(sys.argv[2])
def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
git('init')
samples=['{}','{"global":[],"crates":{},"no_tests":[]}','{"global":[1,2.0,1e999,NaN,null,false,"x",[],{}],"crates":{"\\ud800":{}},"no_tests":["\\ud800","x"]}','[]','null','true','123','9'*100,'1e999','{"global":null}','{"global":false}','{"global":{}}','{"global":"x"}','{"crates":[]}','{"crates":null}','{"crates":false}','{"no_tests":null}','{"no_tests":false}','{"no_tests":"x"}','{"no_tests":[1]}','{"no_tests":[true]}','','[1,]','{"é":}','\ufeff{}','{"global":null,"global":[]}','{"global":[],"global":null}','9'*4301,'{"ignored":'+'9'*100+'}']
fixtures=[(s.encode(),None,False) for s in samples]+[(b'\xff',None,False),(b'\xff\xfe{\0}\0',None,False),(None,None,False),(b'{}',b'{',False),(b'{',b'{}',False),(b'{}',None,True)]
for i,(legacy,new,directory) in enumerate(fixtures):
 base=repo/str(i); base.mkdir(); (base/'marker').touch()
 for name,data in [('.st/rust-test-inputs.json',legacy),('.fractal/rust-test-inputs.json',new)]:
  if data is not None:
   p=base/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data)
 if directory:
  p=base/'.fractal/rust-test-inputs.json'; p.mkdir(parents=True); (p/'marker').touch()
git('add','.'); tree=git('write-tree'); cases=[]
for i in range(len(fixtures)):
 subtree=git('rev-parse',f'{tree}:{i}')
 try:
  v=m.read_inputs(repo,subtree); expected=dict(ok=True,no_tests=[[ord(c) for c in s] for s in v.get('no_tests',[])],global_types=[type(x).__name__ for x in v.get('global',[])],crates=[[ord(c) for c in s] for s in v.get('crates',{})])
 except m.Failure as e: expected=dict(error=str(e))
 cases.append(dict(tree=subtree,expected=expected))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let oracle = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/fractal/scripts/rust-test-keys");
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
    let cases: Vec<Json> = serde_json::from_slice(&out.stdout).unwrap();
    for case in &cases {
        let source = TreeSource {
            repo: repo.path(),
            tree: case["tree"].as_str().unwrap(),
            no_lazy_fetch: true,
        };
        let actual = match source.read_inputs() {
            Ok(inputs) => {
                let types = match inputs.get("global") {
                    Some(Node::Array(ids)) => ids
                        .iter()
                        .map(|id| kind(inputs.document().node(*id)))
                        .collect::<Vec<_>>(),
                    _ => Vec::new(),
                };
                let crates = match inputs.get("crates") {
                    Some(Node::Object(entries)) => entries.keys().collect::<Vec<_>>(),
                    _ => Vec::new(),
                };
                json!({"ok":true,"no_tests":inputs.no_tests().collect::<Vec<_>>(),"global_types":types,"crates":crates})
            }
            Err(e) => {
                assert_eq!(e.reason, "error");
                assert_eq!(
                    e.origin,
                    crate::evidence::legacy_policy::ErrorOrigin::Failure
                );
                json!({"error":e.detail.to_string()})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 35);
}
#[test]
fn ignored_input_metadata_has_approved_unbounded_depth() {
    let text = format!(
        "{{\"ignored\":{}0{}}}",
        "[".repeat(100_000),
        "]".repeat(100_000)
    );
    let inputs = Inputs::parse_bytes(text.as_bytes()).unwrap();
    assert_eq!(inputs.no_tests().count(), 0);
    let out=std::process::Command::new("python3").args(["-c","import json\ns='{\"ignored\":'+('['*100000)+'0'+(']'*100000)+'}'\ntry: json.loads(s)\nexcept RecursionError: pass\nelse: raise AssertionError('expected RecursionError')"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

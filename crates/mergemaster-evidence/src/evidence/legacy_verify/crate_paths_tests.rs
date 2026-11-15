use super::*;
use serde_json::{Value as Json, json};
#[test]
fn declared_paths_match_python_except_approved_mixed_sort_diagnostic() {
    let script = r#"
import importlib.machinery,importlib.util,json,pathlib,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
l=importlib.machinery.SourceFileLoader('keys',sys.argv[1]); spec=importlib.util.spec_from_loader('keys',l); m=importlib.util.module_from_spec(spec); l.exec_module(m)
repo=pathlib.Path(sys.argv[2])
def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
git('init')
root='[package]\nname="root"\n[workspace]\nmembers=["a","b"]\n[workspace.dependencies]\np={path="shared"}\n[dependencies]\na={path="a"}\n[patch.crates-io]\nlib={path="patch"}'
docs={'.':root,'a':'[package]\nname="a"\n[dev-dependencies]\nb={path="../b"}','b':'[package]\nname="b"\n[target.unix.build-dependencies]\np={workspace=true}','shared':'[package]\nname="shared"'}
fixtures=[]
def configured(): return {'root':{'extra':[]},'a':{'extra':[]},'b':{'extra':[]}}
for extra in [[],None,False,0,1,1.5,'é🦀',{'é':1,'\ud800':2},['x'],['x',False],['x',[]],['x',{}]]:
 crates=configured(); crates['root']['extra']=extra; fixtures.append(({'global':[],'crates':crates},root))
for spec in [None,False,0,'',[],{},True,1,'x',[1]]:
 crates=configured(); crates['root']=spec; fixtures.append(({'global':[],'crates':crates},root))
for global_paths in [['x'],['\udc80'],[1],[None],[False],[1.5],[[]],[{}]]:
 fixtures.append(({'global':global_paths,'crates':configured()},root))
crates=configured(); crates['root']['extra']=False
fixtures += [({'global':[1],'crates':crates},root),({'global':[],'crates':{}},root),({'global':['Cargo.lock','!docs','x::selector'],'crates':configured()},root),({'global':[[]],'crates':{}},'[workspace]\nmembers=[]'),({'global':[1],'crates':configured()},root+'\n[build-dependencies]\nmissing={path="absent"}')]
for i,(inputs,root_text) in enumerate(fixtures):
 for directory,text in docs.items():
  path=repo/str(i)/directory/'Cargo.toml'; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(root_text if directory=='.' else text)
git('add','.'); tree=git('write-tree'); cases=[]
for i,(inputs,_) in enumerate(fixtures):
 subtree=git('rev-parse',f'{tree}:{i}'); approved=False
 try: expected=dict(paths={name:[[ord(c) for c in p] for p in paths] for name,paths in m.declared_paths(repo,subtree,inputs).items()})
 except Exception as e:
  expected=dict(error=str(e),kind='Failure' if isinstance(e,m.Failure) else type(e).__name__)
  if isinstance(e,TypeError) and str(e).startswith("'<' not supported"):
   approved=True; expected=dict(error='.st/rust-test-inputs.json: declared path is not a string',kind='Failure')
 cases.append(dict(tree=subtree,inputs=json.dumps(inputs),expected=expected,approved=approved))
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
        let inputs = Inputs::parse_bytes(case["inputs"].as_str().unwrap().as_bytes()).unwrap();
        let actual = match source.declared_paths(&inputs) {
            Ok(paths) => {
                let paths: std::collections::BTreeMap<_, _> = paths
                    .iter()
                    .map(|(name, paths)| {
                        (
                            name,
                            paths
                                .iter()
                                .map(|p| p.borrowed().points().collect::<Vec<_>>())
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect();
                json!({"paths":paths})
            }
            Err(e) => {
                json!({"error":e.detail.to_string(),"kind":match e.origin {crate::evidence::legacy_policy::ErrorOrigin::Failure=>"Failure",crate::evidence::legacy_policy::ErrorOrigin::Exception{class}=>class}})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 35);
    assert_eq!(cases.iter().filter(|c| c["approved"] == true).count(), 5);
}

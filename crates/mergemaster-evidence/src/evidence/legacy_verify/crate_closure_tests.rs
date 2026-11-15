use super::*;
use serde_json::{Value as Json, json};
#[test]
fn iterative_walk_matches_python_cache_and_refusal_order() {
    let script = r#"
import importlib.machinery,importlib.util,json,pathlib,subprocess,sys,tomllib
assert sys.version_info[:3]==(3,14,7)
l=importlib.machinery.SourceFileLoader('keys',sys.argv[1]); spec=importlib.util.spec_from_loader('keys',l); m=importlib.util.module_from_spec(spec); l.exec_module(m)
repo=pathlib.Path(sys.argv[2])
def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
git('init'); fixtures=[]
def manifest(edges): return '[dependencies]\n'+'\n'.join(k+'={path="../'+v+'"}' for k,v in edges)
for edges in [[],[('a','b')],[('a','b'),('b','a')],[('a','b'),('b','c'),('c','a'),('a','d')],[('a','b'),('a','c'),('b','d'),('c','d')]]:
 docs={'.':'','a':'','b':'','c':'','d':''}
 for directory in ['a','b','c','d']: docs[directory]=manifest([(str(i),b) for i,(a,b) in enumerate(edges) if a==directory])
 fixtures.append((docs,'{}',['a','b','c','a','.']))
fixtures += [({'.':'','a':'[dependencies]\nx={path="../missing"}\n[dev-dependencies]\nx={path=123}'},'{}',['a','a']),({'.':'','a':'[dependencies]\nx={path="../missing"}\ny={path=123}'},'{}',['a','a']),({'.':'','a':'target=123\n[dependencies]\nx={path="../missing"}'},'{}',['a','a']),({'.':'','a':'[target.unix.dependencies]\nx={path="../b"}\n[target.windows.build-dependencies]\ny={path="../c"}','b':'[dev-dependencies]\nx={path="../d"}','c':'','d':''},'{}',['a','b']),({'.':'','a':'[dependencies]\nx={workspace=true}','b':''},'{x={path="b"}}',['a','b']),({'.':'','a':'[dependencies]\nx={workspace=true}'},'false',['a','a'])]
for i,(docs,workspace,roots) in enumerate(fixtures):
 for directory,text in docs.items():
  path=repo/str(i)/directory/'Cargo.toml'; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(text)
git('add','.'); tree=git('write-tree'); cases=[]
for i,(docs,workspace,roots) in enumerate(fixtures):
 subtree=git('rev-parse',f'{tree}:{i}'); cache={}; ws=tomllib.loads('v='+workspace)['v']
 for directory in roots:
  try: m.closure(repo,subtree,directory,ws,cache); result=dict(ok=True)
  except Exception as e: result=dict(error=str(e),kind='Failure' if isinstance(e,m.Failure) else type(e).__name__)
  cases.append(dict(group=i,tree=subtree,directory=directory,workspace='v='+workspace,result=result,cache={k:sorted(v) for k,v in cache.items()}))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let oracle = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/fractal/scripts/rust-test-keys");
    let out = crate::pinned_python::command()
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
    let mut cache = ClosureCache::default();
    let mut group = Json::Null;
    for case in &cases {
        if group != case["group"] {
            cache = ClosureCache::default();
            group = case["group"].clone();
        }
        let source = TreeSource {
            repo: repo.path(),
            tree: case["tree"].as_str().unwrap(),
            no_lazy_fetch: true,
        };
        let ws = super::super::toml::parse(case["workspace"].as_str().unwrap()).unwrap();
        let actual = match source.closure(
            case["directory"].as_str().unwrap(),
            ws.get("v"),
            &mut cache,
        ) {
            Ok(()) => json!({"ok":true}),
            Err(e) => {
                json!({"error":e.detail.to_string(),"kind":match e.origin {crate::evidence::legacy_policy::ErrorOrigin::Failure=>"Failure",crate::evidence::legacy_policy::ErrorOrigin::Exception{class}=>class}})
            }
        };
        assert_eq!(actual, case["result"], "{case}");
        let snapshot: std::collections::BTreeMap<_, _> = cache.entries.iter().collect();
        assert_eq!(json!(snapshot), case["cache"], "{case}");
    }
    assert_eq!(cases.len(), 37);
}

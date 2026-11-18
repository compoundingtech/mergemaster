use super::*;
use serde_json::{Value as Json, json};
#[test]
fn layout_and_type_confusion_match_oracle_except_approved_names() {
    let script = r#"
import importlib.machinery,importlib.util,json,pathlib,subprocess,sys,tomllib
assert sys.version_info[:3]==(3,14,7)
l=importlib.machinery.SourceFileLoader('keys',sys.argv[1]); spec=importlib.util.spec_from_loader('keys',l); m=importlib.util.module_from_spec(spec); l.exec_module(m)
repo=pathlib.Path(sys.argv[2])
def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
git('init')
git('config','core.quotePath','true')
values=['123','0','true','false','1.5','nan','1979-05-27','[]','[1]','["*"]','{}','{x=1}',"''","'x'"]
samples=[]
for field in ['name','package','workspace','members','patchpath','exclude']:
 for token in values:
  raw={'name':'[package]\nname='+token,'package':'package='+token,'workspace':'workspace='+token,'members':'[workspace]\nmembers='+token,'patchpath':'[patch.crates-io.lib]\npath='+token,'exclude':'[workspace]\nexclude='+token}[field]
  samples.append((field,raw))
samples += [('normal',s) for s in ['[workspace]\nmembers=["x"]','[workspace]\nmembers=["a/*"]','[workspace]\nmembers=["a/**"]','[workspace]\nmembers=["missing"]','[workspace]\nmembers=["x","x"]','[package]\nname="root"\n[workspace]\nmembers=["x"]','[workspace]\nmembers=["a/*"]\n[patch.crates-io]\nlib={path="a/../patch"}']]
samples += [
 ('order','[workspace]\nmembers=["a/y","x","a/x"]'),
 ('root-order','[package]\nname="root"\n[workspace]\nmembers=["a/y","x"]'),
 ('root-duplicate','[package]\nname="x"\n[workspace]\nmembers=["a/y","a/x"]'),
 ('quoted','[workspace]\nmembers=["a/*"]'),
 ('quoted-unicode','[workspace]\nmembers=["a/*"]')]
for i,(field,raw) in enumerate(samples):
 d=repo/str(i); d.mkdir(); (d/'Cargo.toml').write_text(raw)
 for path,name in [('x','x'),('a/x','x'),('a/y','y')]:
  p=d/path; p.mkdir(parents=True); (p/'Cargo.toml').write_text('[package]\nname='+json.dumps(name))
 if field in ['quoted','quoted-unicode']:
  p=d/'a'/('q"uote' if field=='quoted' else 'café');p.mkdir();(p/'Cargo.toml').write_text('[package]\nname="quoted"')
git('add','.'); tree=git('write-tree'); cases=[]
for i,(field,raw) in enumerate(samples):
 subtree=git('rev-parse',f'{tree}:{i}')
 try:
  members,patched,_=m.layout(repo,subtree); expected=dict(members=list(members.items()),patched=patched)
 except Exception as e: expected=dict(error=str(e),kind='Failure' if isinstance(e,m.Failure) else type(e).__name__)
 approved=field=='name' and not isinstance(tomllib.loads(raw)['package']['name'],str)
 if approved: expected=dict(error='Cargo.toml: package.name is not a string',kind='Failure')
 if field=='order':assert expected['members']==[('y','a/y'),('x','a/x')]
 if field=='root-order':assert expected['members']==[('root','.'),('y','a/y'),('x','x')]
 if field=='root-duplicate':assert expected['members']==[('x','a/x'),('y','a/y')]
 if field in ['quoted','quoted-unicode']:
  assert expected['kind']=='Failure'
  expanded=m.expand_members(repo,subtree,['a/*']);assert any(name.startswith('"a/') for name in expanded)
  assert expected['error']==subtree+':'+expanded[0]+'/Cargo.toml is not readable'
 cases.append(dict(tree=subtree,raw=raw,expected=expected,approved=approved))
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
    for case in &cases {
        let source = TreeSource {
            repo: repo.path(),
            tree: case["tree"].as_str().unwrap(),
            no_lazy_fetch: true,
        };
        let actual = match source.layout() {
            Ok(l) => {
                json!({"members":l.members.into_iter().collect::<Vec<_>>(),"patched":l.patched})
            }
            Err(e) => {
                json!({"error":e.detail.to_string(),"kind":match e.origin {crate::evidence::legacy_policy::ErrorOrigin::Failure=>"Failure",crate::evidence::legacy_policy::ErrorOrigin::Exception{class}=>class}})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 96);
    assert_eq!(cases.iter().filter(|c| c["approved"] == true).count(), 12);
}

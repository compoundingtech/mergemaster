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
  args=[sys.executable,'-I',str(tool),'--repo',str(repo),'--tree',revision,'--verifier',str(verifier),'--json']
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
    let out = crate::pinned_python::command()
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

#[test]
fn member_keys_match_base_first_oracle_and_refusals() {
    let script = r#"
import ast,json,os,pathlib,runpy,subprocess,sys,types
assert sys.version_info[:3]==(3,14,7)
repo=pathlib.Path(sys.argv[2]); root=pathlib.Path(sys.argv[1])
v=runpy.run_path(str(root/'scripts/evidence-verify'))
rtk=types.SimpleNamespace(**runpy.run_path(sys.argv[3]))
scope=dict(os=os,Failure=v['Failure'],project=v['project'],sibling=lambda name:rtk)
module=ast.parse((root/'scripts/evidence-verify').read_text())
exec(compile(ast.Module(body=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='member_keys'],type_ignores=[]),'oracle','exec'),scope)
def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
def write(name,data):
 p=repo/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data)
git('init')
fixtures=[
 ('good',b'[workspace]\nmembers=["z","a"]',b'{"global":["Cargo.toml"],"crates":{"a":{"extra":[".st/settings.json::x"]},"z":{"extra":[]}}}'),
 ('empty',b'[workspace]\nmembers=[]',b'{}'),
 ('missing-manifest',None,b'{}'),
 ('bad-manifest',b'bad = [',b'{}'),
 ('bad-inputs',b'[workspace]\nmembers=[]',b'{'),
 ('bad-shape',b'[workspace]\nmembers=[]',b'[]'),
 ('bad-utf8',b'[workspace]\nmembers=[]',b'\xff'),
 ('no-inputs',b'[workspace]\nmembers=[]',None),
 ('exception',b'[workspace]\nmembers=[]',b'{"global":1}'),
 ('project-missing-old',b'[workspace]\nmembers=["z","a"]',b'{}'),
 ('project-missing-preferred',b'[workspace]\nmembers=["z","a"]',b'{}'),
]
trees={}
for name,manifest,inputs in fixtures:
 prefix=name+'/'
 write(prefix+'marker',b'')
 if manifest is not None: write(prefix+'Cargo.toml',manifest)
 if inputs is not None: write(prefix+'.st/rust-test-inputs.json',inputs)
 for crate in ['z','a']:
  write(prefix+crate+'/Cargo.toml',('[package]\nname="'+crate+'"').encode())
  write(prefix+crate+'/src/lib.rs',b'pub fn fixture() {}')
 write(prefix+'.st/settings.json',b'{"x":1}')
 if name=='project-missing-old': write(prefix+'.st/settings.json',b'{"x":"gone-old"}')
 if name=='project-missing-preferred': write(prefix+'.fractal/settings.json',b'{"x":"gone-preferred"}')
git('add','.'); outer=git('write-tree')
for name,_,_ in fixtures: trees[name]=git('rev-parse',outer+':'+name)
for name,path in [('project-missing-old','.st/settings.json'),('project-missing-preferred','.fractal/settings.json')]:
 oid=git('rev-parse',trees[name]+':'+path)
 (repo/'.git/objects'/oid[:2]/oid[2:]).unlink()
base=trees['good']; raw=f'tree {base}\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nmembers\n'.encode()
commit=subprocess.check_output(['git','-C',str(repo),'hash-object','-t','commit','-w','--stdin'],input=raw).decode().strip()
git('update-ref','refs/heads/accepted',commit); git('symbolic-ref','HEAD','refs/heads/accepted')
pairs=[(base,None),(base,''),(base,base),('missing-tree',base),('missing-tree',trees['bad-inputs'])]
pairs += [(trees[name],base) for name in ['empty','missing-manifest','bad-manifest','project-missing-old','project-missing-preferred']]
pairs += [(base,trees[name]) for name in ['bad-inputs','bad-shape','bad-utf8','no-inputs','exception']]
pairs += [(candidate,accepted) for candidate,accepted in [('HEAD','accepted'),(commit[:12],'HEAD'),('accepted',commit[:12]),(base,'missing-base')]]
cases=[]
for inherited in [None,'0','1']:
 if inherited is None: os.environ.pop('GIT_NO_LAZY_FETCH',None)
 else: os.environ['GIT_NO_LAZY_FETCH']=inherited
 for tree,base in pairs:
  try: expected={'ok':scope['member_keys'](repo,tree,base)}
  except v['Failure'] as e: expected={'class':'Failure','reason':e.reason,'detail':str(e)}
  except Exception as e: expected={'class':type(e).__name__,'detail':str(e)}
  assert os.environ.get('GIT_NO_LAZY_FETCH')==inherited
  cases.append(dict(tree=tree,base=base,expected=expected))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .arg(repo.path())
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/fractal/scripts/rust-test-keys"),
        )
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    for case in &cases {
        let actual = match member_keys(
            repo.path(),
            case["tree"].as_str().unwrap(),
            case["base"].as_str().map(Into::into),
        ) {
            Ok(keys) => {
                json!({"ok":keys.into_iter().collect::<std::collections::BTreeMap<_, _>>()})
            }
            Err(error) => match error.origin {
                crate::evidence::legacy_policy::ErrorOrigin::Failure => {
                    json!({"class":"Failure","reason":error.reason,"detail":error.detail.to_string()})
                }
                crate::evidence::legacy_policy::ErrorOrigin::Exception { class } => {
                    json!({"class":class,"detail":error.detail.to_string()})
                }
            },
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 57);
}

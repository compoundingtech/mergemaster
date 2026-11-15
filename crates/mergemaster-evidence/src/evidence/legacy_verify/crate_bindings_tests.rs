use super::*;
use serde_json::{Value, json};
#[test]
fn accepted_allowance_constructs_member_and_explicit_bindings() {
    let script = r#"
import ast,json,pathlib,runpy,subprocess,sys,types
assert sys.version_info[:3]==(3,14,7)
root=pathlib.Path(sys.argv[1]); repo=pathlib.Path(sys.argv[2])
v=runpy.run_path(str(root/'scripts/evidence-verify'))
rtk=types.SimpleNamespace(**runpy.run_path(sys.argv[3]))
# Retain the actual member implementation, loading the pinned sibling explicitly.
v['member_keys'].__globals__['sibling']=lambda name:rtk
def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
def write(path,data):
 p=repo/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data)
git('init'); trees=[]
for i,inputs in enumerate([b'{}',b'{"no_tests":["a"]}',b'{"no_tests":["z","\\ud800","\\u0000"]}',b'{"no_tests":null}',b'{',b'\xff',None]):
 prefix=str(i)+'/'
 write(prefix+'Cargo.toml',b'[workspace]\nmembers=["z","a"]')
 for name in ['a','z']: write(prefix+name+'/Cargo.toml',('[package]\nname="'+name+'"').encode())
 if inputs is not None: write(prefix+'.st/rust-test-inputs.json',inputs)
git('add','.'); outer=git('write-tree')
for i in range(7): trees.append(git('rev-parse',outer+':'+str(i)))
raw='refs/tags/accepted-'+chr(0xdcff)
adjacent='refs/tags/accepted-'+chr(0xdcc3)+chr(0xdca9)
missing='refs/tags/missing-'+chr(0xdcff)
for ref,tree in [(raw,trees[1]),(adjacent,trees[1]),(missing,trees[6])]: git('update-ref',ref,tree)
cases=[]
for base in [None,'',*trees,'unknown-base',raw,adjacent,missing,'bad'+chr(0xd800),'bad\0','bad\0'+chr(0xd800)]:
 for mode in ['explicit','members']:
  for name in (['a','z','\ud800','\x00'] if mode=='explicit' else ['a']):
   try:
    if mode=='explicit': result=[[list(map(ord,name)),'a'*40,bool(base) and name not in v['zero_test_crates'](repo,base)]]
    else:
     members=v['member_keys'](repo,trees[0],base); allowance=v['zero_test_crates'](repo,base)
     result=[[list(map(ord,n)),k,n not in allowance] for n,k in members.items()]
    expected={'ok':result}
   except v['Failure'] as e: expected={'class':'Failure','reason':e.reason,'detail':str(e)}
   except Exception as e: expected={'class':type(e).__name__,'detail':str(e)}
   if 'detail' in expected: expected['detail']=list(map(ord,expected['detail']))
   if base in [raw,adjacent]: assert 'ok' in expected,(base,mode,expected)
   cases.append(dict(mode=mode,base=list(map(ord,base)) if base is not None else None,name=list(map(ord,name)),tree=trees[0],expected=expected))
for mode in ['explicit','members']:
 base=chr(0xd800)
 try:
  if mode=='explicit': v['zero_test_crates'](str(repo)+'/\0',base)
  else: v['member_keys'](str(repo)+'/\0',trees[0],base)
  raise AssertionError('expected repository NUL refusal')
 except ValueError as e: expected=dict(class_='ValueError',detail=list(map(ord,str(e))))
 expected['class']=expected.pop('class_')
 cases.append(dict(mode=mode,base=[0xd800],name=[97],tree=trees[0],nul_repo=True,expected=expected))
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
        let repo_path = if case["nul_repo"] == true {
            repo.path().join("\0")
        } else {
            repo.path().to_path_buf()
        };
        let base_points: Option<Vec<u32>> = serde_json::from_value(case["base"].clone()).unwrap();
        let base = base_points.as_deref().map(TextRef::Points);
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let parsed = ParsedCrateKey {
            name: TextRef::Points(&name),
            key: std::borrow::Cow::Borrowed("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        };
        let actual = if case["mode"] == "explicit" {
            parsed
                .binding(&repo_path, base)
                .map(|b| json!([[b.name.points().collect::<Vec<_>>(), b.key, b.needs_tests]]))
        } else {
            Members::read(&repo_path, case["tree"].as_str().unwrap(), base).map(|members| {
                json!(
                    members
                        .iter()
                        .map(|(_, b)| {
                            let b = b.unwrap();
                            json!([b.name.points().collect::<Vec<_>>(), b.key, b.needs_tests])
                        })
                        .collect::<Vec<_>>()
                )
            })
        };
        let actual = match actual {
            Ok(bindings) => json!({"ok":bindings}),
            Err(e) => match e.origin {
                crate::evidence::legacy_policy::ErrorOrigin::Failure => {
                    json!({"class":"Failure","reason":e.reason,"detail":e.detail.borrowed().points().collect::<Vec<_>>()})
                }
                crate::evidence::legacy_policy::ErrorOrigin::Exception { class } => {
                    json!({"class":class,"detail":e.detail.borrowed().points().collect::<Vec<_>>()})
                }
            },
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 82);
}

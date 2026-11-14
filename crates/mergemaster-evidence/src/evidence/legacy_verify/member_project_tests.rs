use super::*;
use serde_json::Value;
#[test]
fn member_project_matches_actual_oracle_cli_and_escapes_wire_text() {
    let script = r#"
import contextlib,io,json,pathlib,runpy,subprocess,sys,types
assert sys.version_info[:3]==(3,14,7)
root=pathlib.Path(sys.argv[1]); repo=pathlib.Path(sys.argv[2])
v=runpy.run_path(str(root/'scripts/evidence-verify')); rtk=types.SimpleNamespace(**runpy.run_path(sys.argv[3]))
v['member_keys'].__globals__['sibling']=lambda name:rtk
def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
def write(path,data):
 p=repo/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(data)
git('init'); write('Cargo.toml','[workspace]\nmembers=["z","a","unicode"]')
for directory,name in [('z','z'),('a','a'),('unicode','é😀')]: write(directory+'/Cargo.toml','[package]\nname='+json.dumps(name,ensure_ascii=False))
write('.st/rust-test-inputs.json','{"no_tests":["a"],"policy":"ignored"}')
git('add','.'); tree=git('write-tree'); cases=[]
for check in ['rust-tests','é😀','\ud800','line\n\t\x1b[31m','x'*10000]:
 out=io.StringIO()
 with contextlib.redirect_stdout(out):
  code=v['main'](['--repo',str(repo),'--tree',tree,'--check',check,'--project','--members','--policy-from',tree,'--repository','org/repo'])
 assert code==0
 cases.append(dict(tree=tree,check=list(map(ord,check)),expected=out.getvalue().rstrip('\n')))
# Project output schema branch also retains missing keys. Execute that real branch.
import ast
module=ast.parse((root/'scripts/evidence-verify').read_text()); main=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
branch=next(n for n in ast.walk(main) if isinstance(n,ast.If) and ast.unparse(n.test)=='args.project and args.members')
args=types.SimpleNamespace(repo=repo,check='\udcff\x00',policy_from=tree)
scope=dict(v, args=args, tree=tree, member_keys=lambda *a:{'z':None,'a':'a'*40})
out=io.StringIO()
with contextlib.redirect_stdout(out): exec(compile(ast.Module(body=branch.body[:-1],type_ignores=[]),'oracle','exec'),scope)
cases.append(dict(tree=tree,check=list(map(ord,args.check)),synthetic=True,expected=out.getvalue().rstrip('\n')))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let out = std::process::Command::new("python3")
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
        let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
        let tree = case["tree"].as_str().unwrap();
        let project = if case["synthetic"].as_bool() == Some(true) {
            MemberProject {
                tree,
                check: check.as_slice().into(),
                keys: IndexMap::from([("a".into(), Some("a".repeat(40))), ("z".into(), None)]),
            }
        } else {
            MemberProject::read(repo.path(), tree, check.as_slice().into(), Some(tree)).unwrap()
        };
        let mut actual = String::new();
        crate::evidence::legacy_output::write(&mut actual, |w| project.write_json(w)).unwrap();
        assert_eq!(actual, case["expected"].as_str().unwrap());
        assert!(
            actual
                .chars()
                .all(|c| c.is_ascii() && (c >= ' ' || c == '\n'))
        );
    }
    assert_eq!(cases.len(), 6);
}

#[test]
fn tree_id_validation_precedes_member_keys_for_both_hash_formats() {
    let script = r#"
import contextlib,io,json,pathlib,runpy,subprocess,sys,types
assert sys.version_info[:3]==(3,14,7)
root=pathlib.Path(sys.argv[1]); parent=pathlib.Path(sys.argv[2])
v=runpy.run_path(str(root/'scripts/evidence-verify')); rtk=types.SimpleNamespace(**runpy.run_path(sys.argv[3]))
v['member_keys'].__globals__['sibling']=lambda name:rtk
cases=[]
for fmt in ['sha1','sha256']:
 repo=parent/fmt; repo.mkdir()
 def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
 git('init','--object-format='+fmt)
 (repo/'Cargo.toml').write_text('[package]\nname="fixture"')
 (repo/'.st').mkdir(); (repo/'.st/rust-test-inputs.json').write_text('{}')
 git('add','.'); tree=git('write-tree')
 for target in [tree,'HEAD',tree[:12],tree.upper(),' ',tree+'\n','z'*len(tree)]:
  for base in [None,tree]:
   args=['--repo',str(repo),'--tree',target,'--check','rust-tests','--project','--members']
   if base: args+=['--policy-from',base,'--repository','org/repo']
   out=io.StringIO()
   with contextlib.redirect_stdout(out): code=v['main'](args)
   assert code in [0,1]
   wire=out.getvalue().rstrip('\n'); result=json.loads(wire)
   expected={'wire':wire} if code==0 else dict(reason=result['reason'],detail=result['detail'])
   cases.append(dict(repo=str(repo),tree=target,base=base,expected=expected))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let out = std::process::Command::new("python3")
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
        let actual = match MemberProject::read(
            Path::new(case["repo"].as_str().unwrap()),
            case["tree"].as_str().unwrap(),
            "rust-tests".into(),
            case["base"].as_str(),
        ) {
            Ok(project) => {
                let mut wire = String::new();
                crate::evidence::legacy_output::write(&mut wire, |w| project.write_json(w))
                    .unwrap();
                serde_json::json!({"wire":wire})
            }
            Err(error) => {
                assert_eq!(
                    error.origin,
                    crate::evidence::legacy_policy::ErrorOrigin::Failure
                );
                serde_json::json!({"reason":error.reason,"detail":error.detail.to_string()})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 28);
}

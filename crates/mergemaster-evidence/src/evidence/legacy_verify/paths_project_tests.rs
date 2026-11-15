use super::*;
use serde_json::Value;
#[test]
fn paths_only_project_matches_real_cli_losslessly() {
    let script = r#"
import contextlib,io,json,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify')); parent=pathlib.Path(sys.argv[2]); cases=[]
for fmt in ['sha1','sha256']:
 repo=parent/fmt; repo.mkdir()
 def git(*args): return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
 git('init','--object-format='+fmt)
 (repo/'a').write_text('content'); (repo/'z').write_text('other'); git('add','.'); tree=git('write-tree')
 paths=[None,'',',,,','a',',z,a,a,,','missing','.', '..','a/./b','a/../b','/a','a/*','a?','a[0]','!a','a.json::x','\ud800','\udcff','é'*300,'é'*301,'x'*300,'x'*301,','.join('x'+str(i) for i in range(300)),','.join('x'+str(i) for i in range(301))]
 for p in paths:
  for check in ['project','line\n\x1b\ud800']:
   argv=['--repo',str(repo),'--tree',tree,'--check',check,'--project']
   if p is not None: argv += ['--paths',p]
   out=io.StringIO()
   with contextlib.redirect_stdout(out): code=v['main'](argv)
   result=json.loads(out.getvalue())
   expected={'wire':out.getvalue().rstrip('\n')} if code==0 else dict(reason=result['reason'],detail=list(map(ord,result['detail'])))
   cases.append(dict(repo=str(repo),tree=tree,check=list(map(ord,check)),paths=None if p is None else list(map(ord,p)),expected=expected))
 # Invalid full ID wins over paths validation, even when the repository is absent.
 out=io.StringIO()
 with contextlib.redirect_stdout(out): code=v['main'](['--repo',str(repo/'absent'),'--tree','HEAD','--check','x','--project','--paths','..'])
 result=json.loads(out.getvalue()); assert code==1
 cases.append(dict(repo=str(repo/'absent'),tree='HEAD',check=[120],paths=[46,46],expected=dict(reason=result['reason'],detail=list(map(ord,result['detail'])))))
print(json.dumps(cases))
"#;
    let repo = tempfile::tempdir().unwrap();
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .arg(repo.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in &cases {
        let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
        let paths: Option<Vec<u32>> = serde_json::from_value(case["paths"].clone()).unwrap();
        let actual = match PathsProject::read(
            Path::new(case["repo"].as_str().unwrap()),
            case["tree"].as_str().unwrap(),
            check.as_slice().into(),
            paths.as_deref().map(TextRef::Points),
        ) {
            Ok(project) => {
                let mut wire = String::new();
                crate::evidence::legacy_output::write(&mut wire, |w| project.write_json(w))
                    .unwrap();
                assert!(
                    wire.chars()
                        .all(|c| c.is_ascii() && (c >= ' ' || c == '\n'))
                );
                serde_json::json!({"wire":wire})
            }
            Err(error) => {
                assert_eq!(
                    error.origin,
                    crate::evidence::legacy_policy::ErrorOrigin::Failure
                );
                serde_json::json!({"reason":error.reason,"detail":error.detail.borrowed().points().collect::<Vec<_>>()})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 98);
}

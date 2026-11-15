use super::*;
use serde_json::{Value, json};
fn result(error: PolicyError) -> Value {
    json!({"class":match error.origin { ErrorOrigin::Failure=>"Failure", ErrorOrigin::Exception{class}=>class },"detail":error.detail.to_string()})
}
#[test]
fn bounded_manifests_and_launch_errors_match_real_oracle() {
    if let Ok(expected) = std::env::var("MM_MANIFEST_LAUNCH") {
        let source = TreeSource {
            repo: Path::new("."),
            tree: "HEAD",
            no_lazy_fetch: false,
        };
        let expected: Value = serde_json::from_str(&expected).unwrap();
        assert_eq!(result(source.manifest("").unwrap_err()), expected);
        assert_eq!(result(source.resolve().unwrap_err()), expected);
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p if p.is_dir() else p.parent.parent
m=runpy.run_path(str(p/'tests/fixtures/fractal/scripts/rust-test-keys'));root=pathlib.Path(sys.argv[1]);rows=[]
for fmt in ['sha1','sha256']:
 repo=root/fmt;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
 for size in [1048576,1048577]:
  data=b'#'+b' '*(size-1)
  blob=subprocess.check_output(['git','-C',str(repo),'hash-object','-w','--stdin'],input=data).decode().strip()
  tree=subprocess.check_output(['git','-C',str(repo),'mktree'],input=('100644 blob '+blob+'\tCargo.toml\n').encode()).decode().strip()
  actual=m['manifest'](str(repo),tree,'');rows.append(dict(repo=str(repo),tree=tree,size=size,ok=actual))
errors=[]
for permission in [False,True]:
 directory=root/('permission' if permission else 'missing');directory.mkdir()
 if permission:(directory/'git').write_bytes(b'not executable')
 old=os.environ['PATH'];os.environ['PATH']=str(directory)
 try:m['show']('.', 'HEAD', 'Cargo.toml')
 except Exception as e:errors.append(dict(path=str(directory),expected=dict(detail=str(e),**{'class':type(e).__name__})))
 finally:os.environ['PATH']=old
print(json.dumps(dict(rows=rows,errors=errors)))
"#;
    let out = Command::new("python3")
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Value = serde_json::from_slice(&out.stdout).unwrap();
    for row in cases["rows"].as_array().unwrap() {
        let source = TreeSource {
            repo: Path::new(row["repo"].as_str().unwrap()),
            tree: row["tree"].as_str().unwrap(),
            no_lazy_fetch: false,
        };
        assert_eq!(row["ok"], json!({}));
        if row["size"] == 1_048_576 {
            assert!(source.manifest("").unwrap().is_empty());
        } else {
            let error = source.manifest("").unwrap_err();
            assert_eq!(
                error.resource,
                Some(SourceResource::Toml(toml::Resource::SourceBytes))
            );
            assert_eq!(
                result(error),
                json!({"class":"Failure","detail":"Cargo.toml: TOML source exceeds 1048576 bytes"})
            );
        }
    }
    for row in cases["errors"].as_array().unwrap() {
        let out = Command::new(std::env::current_exe().unwrap()).args(["--exact","evidence::legacy_verify::crate_inputs::capture_tests::bounded_manifests_and_launch_errors_match_real_oracle","--nocapture"])
            .env("PATH",row["path"].as_str().unwrap()).env("MM_MANIFEST_LAUNCH",row["expected"].to_string()).output().unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

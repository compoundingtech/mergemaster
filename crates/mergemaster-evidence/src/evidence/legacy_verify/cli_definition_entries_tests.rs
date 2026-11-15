use super::*;
use serde_json::Value;
use std::process::Command;

#[test]
fn recursive_definition_entries_match_oracle_and_bound_capture() {
    if let Ok(size) = std::env::var("MM_DEFINITION_SIZE") {
        let tree = [0xdcc3, 0xdca9];
        let result = definition_entries(Path::new("."), TextRef::Points(&tree), &["dir".into()]);
        if size.parse::<usize>().unwrap() > super::super::source_resource::LISTING_BYTES {
            let error = result.err().unwrap();
            assert_eq!(
                error.resource,
                Some(SourceResource::TreeListing(NormalizedText::from_points(
                    &tree
                )))
            );
            assert_eq!(
                error.detail.borrowed().points().collect::<Vec<_>>(),
                tree.into_iter()
                    .chain(" exceeds 67108864 bytes".chars().map(u32::from))
                    .collect::<Vec<_>>()
            );
            assert_eq!(error.reason, "error");
            assert_eq!(
                error.origin,
                crate::evidence::legacy_policy::ErrorOrigin::Failure
            );
        } else {
            assert_eq!(result.unwrap().len(), 1);
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p if p.is_dir() else p.parent.parent
m=runpy.run_path(str(p/'scripts/evidence-verify'));root=pathlib.Path(sys.argv[1]);cases=[]
for width in ['sha1','sha256']:
 repo=root/width;repo.mkdir();subprocess.run(['git','init','-q','--object-format='+width,str(repo)],check=True)
 def git(*args,data=None):return subprocess.check_output(['git','-C',str(repo),*args],input=data).strip().decode()
 for name in ['dir/a','dir/b','other','dir/raw-'+chr(0xdcff)]:
  path=repo/name;path.parent.mkdir(exist_ok=True);path.write_bytes(name.encode(errors='surrogateescape'))
 git('add','.');git('update-index','--chmod=+x','dir/b');tree=git('write-tree')
 for rev in [tree,tree[:12]]:
  for paths in [[],['dir'],['dir/a','dir'],['missing'],['other','dir']]:
   entries=m['definition_entries'](str(repo),rev,paths)
   cases.append([str(repo),rev,paths,sorted([[mode,oid,list(name.encode(errors='surrogateescape'))] for mode,oid,name in entries])])
shim=root/'shim';shim.mkdir();program=shim/'git'
program.write_text('#!'+sys.executable+'''\nimport os
header=b'100644 blob '+b'a'*40+b'\\tdir/'
os.write(1,header)
n=int(os.environ['MM_DEFINITION_SIZE'])-len(header)-1
while n:
 sent=os.write(1,b'x'*min(n,65536));n-=sent
os.write(1,b'\\0')
''');program.chmod(0o700)
os.environ['PATH']=str(shim)
for size in [67108864,67108865]:
 os.environ['MM_DEFINITION_SIZE']=str(size)
 assert len(m['definition_entries']('.',chr(0xdcc3)+chr(0xdca9),['dir']))==1
print(json.dumps(cases))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let paths: Vec<String> = serde_json::from_value(case[2].clone()).unwrap();
        let entries = definition_entries(
            Path::new(case[0].as_str().unwrap()),
            TextRef::Str(case[1].as_str().unwrap()),
            &paths,
        )
        .unwrap();
        let actual: Vec<_> = entries
            .into_iter()
            .map(|e| serde_json::json!([e.mode, e.oid, e.path]))
            .collect();
        assert_eq!(serde_json::json!(actual), case[3]);
    }
    for size in [67108864, 67108865] {
        let output = Command::new(std::env::current_exe().unwrap()).args(["--exact", "evidence::legacy_verify::cli_lane_git::tests::recursive_definition_entries_match_oracle_and_bound_capture", "--nocapture"])
            .env("PATH", root.path().join("shim")).env("MM_DEFINITION_SIZE", size.to_string()).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

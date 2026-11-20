use super::super::source_resource::SOURCE_BYTES;
use super::*;
use serde_json::Value;
#[test]
fn raw_tree_reads_are_bounded_and_match_oracle_below_limit() {
    if let Ok(size) = std::env::var("MM_TREE_CAPTURE_DRIVER") {
        let size: usize = size.parse().unwrap();
        let source = TreeSource {
            repo: Path::new("."),
            tree: "HEAD",
            no_lazy_fetch: false,
        };
        let result = source.resolve();
        if size == SOURCE_BYTES {
            assert_eq!(result.unwrap().len(), size);
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.resource,
                Some(SourceResource::RawBlob("HEAD^{tree}".into()))
            );
            assert_eq!(error.detail, "HEAD^{tree} exceeds 1048576 bytes");
            assert_eq!(error.origin, ErrorOrigin::Failure);
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import hashlib,json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
m=runpy.run_path(sys.argv[2]);rows=[];root=pathlib.Path(sys.argv[1])
for fmt in ['sha1','sha256']:
 repo=root/fmt;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
 def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data).decode().strip()
 for size in [1048576,1048577]:
  data=b'{}'+b' '*(size-2);blob=git('hash-object','-w','--stdin',data=data)
  subtree=git('mktree',data=('100644 blob '+blob+'\trust-test-inputs.json\n').encode())
  tree=git('mktree',data=('040000 tree '+subtree+'\t.st\n').encode())
  assert m['read_inputs'](str(repo),tree)=={}
  got=m['show'](str(repo),tree,'.st/rust-test-inputs.json')
  rows.append(dict(repo=str(repo),tree=tree,size=size,digest=hashlib.sha256(got).hexdigest()))
shim=root/'shim';shim.mkdir();program=shim/'git'
program.write_text('#!'+sys.executable+"\nimport os;os.write(2,b'e'*1048577);os.write(1,b'x'*int(os.environ['MM_TREE_CAPTURE_DRIVER']))\n");program.chmod(0o700)
for size in [1048576,1048577]:
 env=dict(os.environ,PATH=str(shim),MM_TREE_CAPTURE_DRIVER=str(size))
 done=subprocess.run(['git','-C','.','rev-parse','--verify','--end-of-options','HEAD^{tree}'],capture_output=True,text=True,env=env)
 assert done.returncode==0 and len(done.stdout.strip())==size
print(json.dumps(dict(rows=rows,shim=str(shim))))
"#;
    let out = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .arg(crate::pinned_python::keys_oracle())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Value = serde_json::from_slice(&out.stdout).unwrap();
    for row in cases["rows"].as_array().unwrap() {
        let tree = row["tree"].as_str().unwrap();
        let source = TreeSource {
            repo: Path::new(row["repo"].as_str().unwrap()),
            tree,
            no_lazy_fetch: false,
        };
        let shown = source.show(INPUTS_PATH);
        if row["size"] == SOURCE_BYTES {
            use sha2::{Digest, Sha256};
            assert_eq!(
                format!("{:x}", Sha256::digest(shown.unwrap().unwrap())),
                row["digest"].as_str().unwrap()
            );
            assert!(source.read_inputs().is_ok());
            assert_eq!(source.resolve().unwrap(), tree);
        } else {
            for error in [shown.unwrap_err(), source.read_inputs().err().unwrap()] {
                assert_eq!(
                    error.resource,
                    Some(SourceResource::RawBlob(
                        format!("{tree}:{INPUTS_PATH}").into()
                    ))
                );
                assert_eq!(
                    error.detail.to_string(),
                    format!("{tree}:{INPUTS_PATH} exceeds 1048576 bytes")
                );
            }
        }
    }
    for size in [SOURCE_BYTES, SOURCE_BYTES + 1] {
        let out = Command::new(std::env::current_exe().unwrap()).args(["--exact","evidence::legacy_verify::crate_inputs::tree_capture_tests::raw_tree_reads_are_bounded_and_match_oracle_below_limit","--nocapture"])
            .env("PATH",cases["shim"].as_str().unwrap()).env("MM_TREE_CAPTURE_DRIVER",size.to_string()).output().unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

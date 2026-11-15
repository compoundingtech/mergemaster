use super::super::source_resource::SOURCE_BYTES;
use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[test]
fn raw_blob_identity_keeps_original_adjacent_surrogates() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import hashlib,json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p/'scripts/evidence-verify' if p.is_dir() else p
v=runpy.run_path(str(p));rows=[]
for fmt in ['sha1','sha256']:
 for directory in ['.st','.fractal']:
  repo=pathlib.Path(sys.argv[1])/(fmt+directory);subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
  def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data).decode().strip()
  for size in [1048576,1048577]:
   data=b'x'*size;blob=git('hash-object','-w','--stdin',data=data)
   subtree=git('mktree',data=('100644 blob '+blob+'\tother.json\n').encode())
   tree=git('mktree',data=('040000 tree '+subtree+'\t'+directory+'\n').encode())
   scalar='refs/snapshots/é'+str(size);original='refs/snapshots/\udcc3\udca9'+str(size)
   git('update-ref',scalar,tree)
   got=v['config_blob'](str(repo),original,'.st/other.json');assert got==data
   rows.append(dict(repo=str(repo),revision=list(map(ord,original)),path=directory+'/other.json',size=size,digest=hashlib.sha256(got).hexdigest()))
print(json.dumps(rows))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 8);
    for row in rows {
        let revision: Vec<u32> = serde_json::from_value(row["revision"].clone()).unwrap();
        let result = blob(
            Path::new(row["repo"].as_str().unwrap()),
            TextRef::Points(&revision),
            ".st/other.json",
        );
        if row["size"] == SOURCE_BYTES {
            let bytes = result.unwrap();
            assert_eq!(bytes.len(), SOURCE_BYTES);
            assert_eq!(
                format!("{:x}", Sha256::digest(bytes)),
                row["digest"].as_str().unwrap()
            );
        } else {
            let spec: Vec<u32> = revision
                .into_iter()
                .chain(std::iter::once(58))
                .chain(row["path"].as_str().unwrap().chars().map(u32::from))
                .collect();
            let error = result.unwrap_err();
            assert_eq!(
                error.resource,
                Some(SourceResource::RawBlob(NormalizedText::Codepoints(
                    spec.clone()
                )))
            );
            assert!(
                error.detail.borrowed().points().eq(spec
                    .into_iter()
                    .chain(" exceeds 1048576 bytes".chars().map(u32::from)))
            );
            assert_eq!(error.origin, ErrorOrigin::Failure);
            assert_eq!(error.reason, "error");
        }
    }
}

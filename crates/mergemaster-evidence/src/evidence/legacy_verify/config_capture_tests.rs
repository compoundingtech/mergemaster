use super::super::{policy_loader, source_resource::SOURCE_BYTES};
use super::*;
use serde_json::Value;
#[test]
fn document_capture_boundaries_match_real_git_oracle() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import hashlib,json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p/'scripts/evidence-verify' if p.is_dir() else p
v=runpy.run_path(str(p));rows=[]
for fmt in ['sha1','sha256']:
 repo=pathlib.Path(sys.argv[1])/fmt;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
 def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data).decode().strip()
 for directory in ['.st','.fractal']:
  for size in [1048576,1048577]:
   data=b'{}'+b' '*(size-2);blob=git('hash-object','-w','--stdin',data=data)
   names=['evidence-skip-policy.json','required-lanes.json','other.json']
   subtree=git('mktree',data=''.join('100644 blob '+blob+'\t'+name+'\n' for name in names).encode())
   tree=git('mktree',data=('040000 tree '+subtree+'\t'+directory+'\n').encode())
   for operation,legacy in [('policy','.st/evidence-skip-policy.json'),('lanes','.st/required-lanes.json'),('raw','.st/other.json')]:
    got=v['config_blob'](str(repo),tree,legacy)
    if operation=='policy':assert got.decode()==data.decode()
    if operation=='lanes':assert v['read_lanes'](str(repo),tree)==data.decode()
    rows.append(dict(repo=str(repo),tree=tree,operation=operation,legacy=legacy,path=directory+'/'+legacy.split('/')[-1],size=size,digest=hashlib.sha256(got).hexdigest()))
print(json.dumps(rows))
"#;
    let out = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.len(), 24);
    for row in rows {
        let repo = Path::new(row["repo"].as_str().unwrap());
        let tree = row["tree"].as_str().unwrap();
        let operation = row["operation"].as_str().unwrap();
        let result = match operation {
            "policy" => policy_loader::read_policy(repo, tree).map(String::into_bytes),
            "lanes" => lanes(repo, tree.into()).map(String::into_bytes),
            "raw" => blob(repo, tree.into(), row["legacy"].as_str().unwrap()),
            _ => unreachable!(),
        };
        if row["size"] == SOURCE_BYTES {
            use sha2::{Digest, Sha256};
            let bytes = result.unwrap();
            assert_eq!(bytes.len(), SOURCE_BYTES);
            assert_eq!(
                format!("{:x}", Sha256::digest(bytes)),
                row["digest"].as_str().unwrap()
            );
        } else {
            let resource = match operation {
                "policy" => SourceResource::PolicyJson(PolicyResource::SourceBytes),
                "lanes" => SourceResource::LaneJson(PolicyResource::SourceBytes),
                _ => SourceResource::RawBlob(
                    format!("{tree}:{}", row["path"].as_str().unwrap()).into(),
                ),
            };
            let error = result.unwrap_err();
            assert_eq!(error.resource, Some(resource.clone()));
            assert_eq!(error.detail, resource.detail());
            assert_eq!(error.reason, "error");
            assert_eq!(error.origin, ErrorOrigin::Failure);
        }
    }
}
#[test]
fn raw_config_metadata_and_allowance_blobs_are_bounded() {
    use super::super::zero_test_crates::zero_test_crates;
    if let Ok(size) = std::env::var("MM_RAW_CONFIG_SIZE") {
        let size: usize = size.parse().unwrap();
        for result in [
            path(Path::new("."), "HEAD~1".into(), ".st/rust-test-inputs.json")
                .map(|p| assert!(p.is_none())),
            zero_test_crates(Path::new("."), "HEAD~1").map(|names| assert!(names.is_empty())),
        ] {
            if size == SOURCE_BYTES {
                result.unwrap();
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error.resource,
                    Some(SourceResource::RawBlob("HEAD~1".into()))
                );
                assert_eq!(error.detail, "HEAD~1 exceeds 1048576 bytes");
                assert_eq!(error.origin, ErrorOrigin::Failure);
                assert_eq!(error.reason, "error");
            }
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p/'scripts/evidence-verify' if p.is_dir() else p
v=runpy.run_path(str(p));root=pathlib.Path(sys.argv[1]);rows=[]
for fmt in ['sha1','sha256']:
 repo=root/fmt;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
 def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data).decode().strip()
 for directory in ['.st','.fractal']:
  for size in [1048576,1048577]:
   prefix=b'{"no_tests":["a","\\ud800"]}';data=prefix+b' '*(size-len(prefix))
   blob=git('hash-object','-w','--stdin',data=data)
   subtree=git('mktree',data=('100644 blob '+blob+'\trust-test-inputs.json\n').encode())
   tree=git('mktree',data=('040000 tree '+subtree+'\t'+directory+'\n').encode())
   assert v['zero_test_crates'](str(repo),tree)=={'a','\ud800'}
   rows.append(dict(repo=str(repo),tree=tree,size=size,path=directory+'/rust-test-inputs.json'))
shim=root/'shim';shim.mkdir();program=shim/'git'
program.write_text('#!'+sys.executable+"\nimport os;os.write(1,b'x'*int(os.environ['MM_RAW_CONFIG_SIZE']))\n");program.chmod(0o700)
os.environ['PATH']=str(shim)
for size in [1048576,1048577]:
 os.environ['MM_RAW_CONFIG_SIZE']=str(size)
 assert v['config_path']('.', 'HEAD~1','.st/rust-test-inputs.json') is None
 assert v['zero_test_crates']('.', 'HEAD~1')==set()
print(json.dumps(dict(rows=rows,shim=str(shim))))
"#;
    let out = std::process::Command::new("python3")
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
    assert_eq!(cases["rows"].as_array().unwrap().len(), 8);
    for row in cases["rows"].as_array().unwrap() {
        let tree = row["tree"].as_str().unwrap();
        let result = zero_test_crates(Path::new(row["repo"].as_str().unwrap()), tree);
        if row["size"] == SOURCE_BYTES {
            assert_eq!(
                result.unwrap(),
                std::collections::BTreeSet::from([vec![97], vec![0xd800]])
            );
        } else {
            let error = result.unwrap_err();
            let resource =
                SourceResource::RawBlob(format!("{tree}:{}", row["path"].as_str().unwrap()).into());
            assert_eq!(error.resource, Some(resource.clone()));
            assert_eq!(error.detail, resource.detail());
            assert_eq!(error.origin, ErrorOrigin::Failure);
        }
    }
    for size in [SOURCE_BYTES, SOURCE_BYTES + 1] {
        let out = std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "evidence::legacy_verify::cli_config::capture_tests::raw_config_metadata_and_allowance_blobs_are_bounded", "--nocapture"])
            .env("PATH",cases["shim"].as_str().unwrap()).env("MM_RAW_CONFIG_SIZE",size.to_string()).output().unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

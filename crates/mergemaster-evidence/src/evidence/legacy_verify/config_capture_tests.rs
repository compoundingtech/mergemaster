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

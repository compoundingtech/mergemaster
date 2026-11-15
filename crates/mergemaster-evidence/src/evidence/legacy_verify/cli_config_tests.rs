use super::*;
use serde_json::{Value, json};
#[test]
fn config_and_lane_reads_match_real_oracle() {
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p/'scripts/evidence-verify' if p.is_dir() else p
v=runpy.run_path(str(p)); rows=[]
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[1])/fmt;root.mkdir()
 for layout,data in [('absent',b''),('legacy',b'legacy'),('preferred',b'preferred'),('both',b'both'),('invalid',b'\xff'),('bom',b'\xef\xbb\xbf{}')]:
  repo=root/layout;subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
  def git(*a,data=None):return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
  git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
  blob=git('hash-object','-w','--stdin',data=data)
  subtree=git('mktree',data=('100644 blob '+blob+'\trequired-lanes.json\n').encode())
  dirs=[] if layout=='absent' else ['.st','.fractal'] if layout=='both' else ['.fractal'] if layout=='preferred' else ['.st']
  tree=git('mktree',data=''.join('040000 tree '+subtree+'\t'+d+'\n' for d in dirs).encode())
  commit=git('commit-tree',tree,data=b'fixture');git('update-ref','refs/heads/main',commit);git('symbolic-ref','HEAD','refs/heads/main')
  revisions=[commit,'HEAD','main',commit[:12],'missing','HEAD\0','HEAD\udcff','HEAD\ud800','HEAD\0\ud800'] if layout=='legacy' else [commit]
  for revision in revisions:
   for op in ['path','blob','lanes']:
    try:
     result= v['config_path'](str(repo),revision,'.st/required-lanes.json') if op=='path' else v['config_blob'](str(repo),revision,'.st/required-lanes.json') if op=='blob' else v['read_lanes'](str(repo),revision)
     expected={'ok':list(result) if isinstance(result,bytes) else list(map(ord,result)) if result is not None else None}
    except Exception as e:
     expected={'origin':'Failure' if isinstance(e,v['Failure']) else type(e).__name__,'detail':list(map(ord,str(e)))}
     if isinstance(e,v['Failure']):expected['reason']=e.reason
    rows.append(dict(repo=str(repo),revision=list(map(ord,revision)),op=op,expected=expected))
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
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
    assert_eq!(rows.len(), 84);
    for row in rows {
        let repo = Path::new(row["repo"].as_str().unwrap());
        let points: Vec<u32> = serde_json::from_value(row["revision"].clone()).unwrap();
        let revision = TextRef::Points(&points);
        let actual = match row["op"].as_str().unwrap() {
            "path" => path(repo, revision, ".st/required-lanes.json").map(
                |value| json!({"ok":value.map(|s|s.chars().map(u32::from).collect::<Vec<_>>())}),
            ),
            "blob" => {
                blob(repo, revision, ".st/required-lanes.json").map(|value| json!({"ok":value}))
            }
            "lanes" => lanes(repo, revision)
                .map(|value| json!({"ok":value.chars().map(u32::from).collect::<Vec<_>>()})),
            _ => unreachable!(),
        }
        .unwrap_or_else(|e| {
            let origin = match e.origin {
                ErrorOrigin::Failure => "Failure",
                ErrorOrigin::Exception { class } => class,
            };
            let mut value =
                json!({"origin":origin,"detail":e.detail.borrowed().points().collect::<Vec<_>>()});
            if e.origin == ErrorOrigin::Failure {
                value["reason"] = json!(e.reason);
            }
            value
        });
        assert_eq!(actual, row["expected"], "{row}");
    }
}

use super::*;
use serde_json::{Value, json};
#[test]
fn strict_policy_loader_matches_real_git_bytes_and_numbers() {
    let script = r#"
import json,pathlib,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); rows=[]
entry={'trust_levels':['agent'],'kinds':{'wrapper':{'command':['true']}}}
valid=json.dumps({'version':1,'checks':{'check':entry}}).encode()
values=[('valid',valid),('invalid-byte',b'\xff'),('invalid-after-json',valid+b'\xff'),('bom',b'\xef\xbb\xbf'+valid),('utf16',valid.decode().encode('utf-16')),('empty',b''),('malformed',b'{')]
for number in ['NaN','-0','1e309','Infinity']:
 for field in ['version','max_age_s','sample_one_in','other']:
  doc={'version':1,'checks':{'check':dict(entry)}}
  if field=='version': doc['version']='NUMBER'
  elif field=='other': doc['checks']['other']='NUMBER'
  else: doc['checks']['check'][field]='NUMBER'
  values.append((number+'/'+field,json.dumps(doc).replace('"NUMBER"',number).encode()))
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[2])/fmt; root.mkdir()
 for i,(label,data) in enumerate(values):
  for layout in ['legacy','preferred','both-valid','both-invalid','absent'] if i==0 else ['legacy']:
   repo=root/(str(i)+'-'+layout); subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
   def git(*a,data=None): return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
   git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
   def blob(data): return git('hash-object','-w','--stdin',data=data)
   def tree(data=b''): return git('mktree',data=data)
   entries=[]
   for directory,content in [('.st',data),('.fractal',b'\xff' if layout=='both-invalid' else data)]:
    if layout=='absent' or layout=='legacy' and directory!='.st' or layout=='preferred' and directory!='.fractal': continue
    subtree=tree(('100644 blob '+blob(content)+'\tevidence-skip-policy.json\n').encode()); entries.append(('040000 tree '+subtree+'\t'+directory+'\n').encode())
   current=tree(b''.join(entries)); commit=git('commit-tree',current,data=b'policy'); git('update-ref','refs/heads/main',commit); git('symbolic-ref','HEAD','refs/heads/main')
   for revision in [commit,'HEAD','main',commit[:12],commit.upper(),'missing','HEAD\0','HEAD\udcff','HEAD\ud800','HEAD\0\ud800','😀\ud800','repo-nul:HEAD\ud800'] if label=='valid' and layout=='legacy' else [commit]:
    target=str(repo)+('\0' if revision.startswith('repo-nul:') else ''); revision=revision.removeprefix('repo-nul:')
    try:
     text=v['read_policy'](target,revision)
     try: v['policy_rules'](text,'check','fixture'); parsed={'accepted':True}
     except v['Failure'] as e: parsed={'reason':e.reason,'detail':list(map(ord,str(e))),'origin':'Failure'}
     expected={'read':list(map(ord,text)),'parsed':parsed}
    except v['Failure'] as e: expected={'reason':e.reason,'detail':list(map(ord,str(e))),'origin':'Failure'}
    except Exception as e: expected={'origin':type(e).__name__,'detail':list(map(ord,str(e)))}
    rows.append(dict(repo=target,revision=list(map(ord,revision)),label=label+'/'+layout,expected=expected))
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
    let out = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.len(), 76);
    for row in rows {
        let repo = Path::new(row["repo"].as_str().unwrap());
        let points: Vec<u32> = serde_json::from_value(row["revision"].clone()).unwrap();
        let revision = TextRef::Points(&points);
        let error = |e: PolicyError| {
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
        };
        let actual = match read_policy(repo, revision) {
            Err(e) => error(e),
            Ok(text) => {
                let parsed =
                    match load(repo, revision, "check").and_then(|doc| doc.into_rules("fixture")) {
                        Ok(_) => json!({"accepted":true}),
                        Err(e) => error(e),
                    };
                json!({"read":text.chars().map(u32::from).collect::<Vec<_>>(),"parsed":parsed})
            }
        };
        assert_eq!(
            actual, row["expected"],
            "{} revision={points:?}",
            row["label"]
        );
    }
}

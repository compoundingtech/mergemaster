use super::*;
#[test]
fn members_shadow_log_matches_complete_signed_git_oracle() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,pathlib,runpy,subprocess,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); root=pathlib.Path(sys.argv[2]); rows=[]
for fmt in ['sha1','sha256']:
 d=root/fmt; d.mkdir(); key=d/'key'; subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 keys=d/'keys'; keys.write_text('log/fixture '+key.with_suffix('.pub').read_text())
 for mode in ['absent','unsigned','stale','empty','one','six','tree-listed','key-listed','missing','dedup-missing','invalid-key','naive-aware','aware-naive','naive','aware','mixed-invalid','invalid-mixed','tie','unreadable']:
  repo=d/('repo-'+mode); subprocess.run(['git','init','-q','--object-format='+fmt,str(repo)],check=True)
  def git(*a,data=None): return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
  git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
  tree=git('mktree',data=b''); record=git('commit-tree',tree,data=b'record'); k='b'*40
  names=['z','a','c','b','y','x'] if mode=='six' else ['b','a'] if mode in ['naive-aware','aware-naive','naive','aware','mixed-invalid','invalid-mixed','tie','unreadable','dedup-missing'] else ['a']
  if mode in ['mixed-invalid','invalid-mixed']: names+=['c']
  if mode=='empty': names=[]
  members={n:(k,record,'2026-01-01T00:00:00Z') for n in names}
  if mode=='invalid-key': members={'a':('invalid',record,None)}
  for i,n in enumerate(sorted(members)):
   obs=('2026-01-01' if mode=='naive' or (mode in ['naive-aware','mixed-invalid'] and i==0) or (mode=='aware-naive' and i==1) else '2026-01-01T00:00:00Z')
   if (mode=='mixed-invalid' and i==2) or mode=='unreadable' or (mode=='invalid-mixed' and i==0): obs='bad'
   if mode=='invalid-mixed' and i==1: obs='2026-01-01'
   if mode!='invalid-key': members[n]=(k,record,obs)
  paths={}
  if mode in ['tree-listed','missing','dedup-missing']: paths['trees/'+tree[:2]+'/'+tree]='record '+record+' check x y z\n'
  if mode in ['key-listed','dedup-missing']: paths['keys/check/'+k[:2]+'/'+k]='record '+record+' check x y z\n'
  for p,s in paths.items(): f=repo/p; f.parent.mkdir(parents=True,exist_ok=True); f.write_text(s)
  if paths: git('add','.'); logtree=git('write-tree')
  else: logtree=tree
  args=['commit-tree',logtree] if mode=='unsigned' else ['-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',logtree]
  head=git(*args,data=('as_of=2025-01-01T00:00:00Z' if mode=='stale' else 'as_of=2026-01-01T00:05:00Z').encode())
  if mode!='absent': git('update-ref',v['LOG_REF'],head)
  if mode=='tree-listed': git('update-ref','refs/tags/evidence/'+tree+'/'+record,record)
  if mode=='key-listed': git('update-ref','refs/tags/evidence/input/check/'+k+'/'+record,record)
  try: expected=v['members_log_view'](str(repo),str(keys),tree,'check',members,v['parse_time']('2026-01-01T00:05:00Z'))
  except Exception as e: expected=dict(exception=type(e).__name__,detail=str(e))
  rows.append(dict(repo=str(repo),keys=str(keys),tree=tree,members=members,expected=expected))
print(json.dumps(rows))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_PARITY_ORACLE").unwrap())
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let now = zoned_time_micros(
        &"2026-01-01T00:05:00Z"
            .chars()
            .map(u32::from)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for row in rows {
        let members = row["members"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(n, v)| {
                (
                    n.clone(),
                    Member {
                        key: v[0].as_str(),
                        chosen: v[1].as_str(),
                        observed: v[2].as_str(),
                    },
                )
            })
            .collect();
        let actual = match read(
            Path::new(row["repo"].as_str().unwrap()),
            Path::new(row["keys"].as_str().unwrap()),
            row["tree"].as_str().unwrap(),
            "check",
            &members,
            now,
            600,
        ) {
            Ok(view) => serde_json::to_value(view).unwrap(),
            Err(e) => {
                let crate::evidence::legacy_policy::ErrorOrigin::Exception { class } = e.origin
                else {
                    panic!("{e:?}")
                };
                serde_json::json!({"exception":class,"detail":e.detail.to_string()})
            }
        };
        assert_eq!(actual, row["expected"], "{row}");
    }
}

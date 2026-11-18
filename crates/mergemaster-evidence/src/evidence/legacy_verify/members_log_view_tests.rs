use super::*;
#[test]
fn member_log_times_preserve_surrogate_separators_and_complete_metadata() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,pathlib,runpy,subprocess,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); root=pathlib.Path(sys.argv[2]); rows=[]
for fmt in ['sha1','sha256']:
 d=root/fmt; d.mkdir(); key=d/'key'; subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 keys=d/'keys'; keys.write_text('log/fixture '+key.with_suffix('.pub').read_text())
 for mode in ['absent','unsigned','stale','empty','one','six','tree-listed','key-listed','missing','dedup-missing','invalid-key','naive-aware','aware-naive','naive','aware','mixed-invalid','invalid-mixed','tie','unreadable','surrogate','mixed-surrogate','surrogate-tie']:
  repo=d/('repo-'+mode); subprocess.run(['git','init','-q','--object-format='+fmt,str(repo)],check=True)
  def git(*a,data=None): return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
  git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
  tree=git('mktree',data=b''); record=git('commit-tree',tree,data=b'record'); k='b'*40
  names=['z','a','c','b','y','x'] if mode=='six' else ['b','a'] if mode in ['naive-aware','aware-naive','naive','aware','mixed-invalid','invalid-mixed','tie','unreadable','dedup-missing','mixed-surrogate','surrogate-tie'] else ['a']
  if mode in ['mixed-invalid','invalid-mixed']: names+=['c']
  if mode=='empty': names=[]
  members={n:(k,record,'2026-01-01T00:00:00Z') for n in names}
  if mode=='invalid-key': members={'a':('invalid',record,None)}
  for i,n in enumerate(sorted(members)):
   obs=('2026-01-01' if mode=='naive' or (mode in ['naive-aware','mixed-invalid'] and i==0) or (mode=='aware-naive' and i==1) else '2026-01-01T00:00:00Z')
   if (mode=='mixed-invalid' and i==2) or mode=='unreadable' or (mode=='invalid-mixed' and i==0): obs='bad'
   if mode=='invalid-mixed' and i==1: obs='2026-01-01'
   if mode=='surrogate' or (mode in ['mixed-surrogate','surrogate-tie'] and i==0): obs='2026-01-01\ud80000:01:00Z'
   if mode=='mixed-surrogate' and i==1: obs='2026-01-01T00:02:00Z'
   if mode=='surrogate-tie' and i==1: obs='2026-01-01T00:01:00Z'
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
  try: expected=dict(wire=json.dumps(v['members_log_view'](str(repo),str(keys),tree,'check',members,v['parse_time']('2026-01-01T00:05:00Z')),indent=2))
  except Exception as e: expected=dict(exception=type(e).__name__,detail=str(e))
  members={n:(key,chosen,None if obs is None else list(map(ord,obs))) for n,(key,chosen,obs) in members.items()}
  rows.append(dict(repo=str(repo),keys=str(keys),tree=tree,members=members,expected=expected))
print(json.dumps(rows))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
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
        let times: BTreeMap<_, Vec<u32>> = row["members"]
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(n, v)| {
                Some((
                    n.clone(),
                    v[2].as_array()?
                        .iter()
                        .map(|p| p.as_u64().unwrap() as u32)
                        .collect(),
                ))
            })
            .collect();
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
                        observed: times.get(n).map(|p| TextRef::Points(p)),
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
            Ok(view) => {
                let mut wire = String::new();
                crate::evidence::legacy_output::write(&mut wire, |w| {
                    w.object(|o| view.write_fields(o))
                })
                .unwrap();
                serde_json::json!({"wire":wire})
            }
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

use super::*;
#[test]
fn signed_log_metadata_matches_real_git_oracle() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,pathlib,runpy,subprocess,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); root=pathlib.Path(sys.argv[2]); rows=[]
boundary=[sign*((1<<e)*1000000+1000000+d) for e in [34,35,36,37] for d in range(-7,8) for sign in ([1,-1] if e<=35 else [1])]
for fmt in ['sha1','sha256']:
 d=root/fmt; d.mkdir(); key=d/'key'; subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 keys=d/'keys'; keys.write_text('log/fixture '+key.with_suffix('.pub').read_text())
 for mode in ['absent','unsigned','wrong-principal','no-stamp','bad-stamp','naive','old','future','edge-old','edge-future','ok','missing','unlogged','chosen','input-missing','input-chosen','negative-fraction','positive-fraction']+['boundary'+str(i) for i in range(len(boundary))]:
  repo=d/('repo-'+mode); subprocess.run(['git','init','-q','--object-format='+fmt,str(repo)],check=True)
  def git(*a,data=None): return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
  git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
  empty=git('mktree',data=b''); record=git('commit-tree',empty,data=b'record'); tree=empty; ik='b'*40; chosen=None
  if mode=='wrong-principal': keys.write_text('agent/fixture '+key.with_suffix('.pub').read_text())
  else: keys.write_text('log/fixture '+key.with_suffix('.pub').read_text())
  stamp={'no-stamp':'nothing','bad-stamp':'as_of=no','naive':'as_of=2026-01-01T00:05:00','old':'as_of=2025-12-31T23:54:59Z','future':'as_of=2026-01-01T00:07:01Z','edge-old':'as_of=2025-12-31T23:55:00Z','edge-future':'as_of=2026-01-01T00:07:00Z','negative-fraction':'as_of=2026-01-01T00:05:00.999999Z','positive-fraction':'as_of=2026-01-01T00:04:59.000001Z'}.get(mode,'as_of=2026-01-01T00:05:00Z')
  micros=boundary[int(mode[8:])] if mode.startswith('boundary') else 1767225900000000; max_age=abs(micros)//1000000 if mode.startswith('boundary') else 600
  if mode.startswith('boundary'): stamp='as_of=1970-01-01T00:00:00Z'
  if mode in ['unlogged','chosen','input-chosen']: chosen=record
  paths={}
  if mode in ['missing','chosen']: paths['trees/'+tree[:2]+'/'+tree]='record '+record+' check x y z\n'
  if mode in ['input-missing','input-chosen']: paths['keys/check/'+ik[:2]+'/'+ik]='record '+record+' check x y z\n'
  for p,s in paths.items(): f=repo/p; f.parent.mkdir(parents=True,exist_ok=True); f.write_text(s)
  if paths: git('add','.'); logtree=git('write-tree')
  else: logtree=empty
  args=['commit-tree',logtree]
  if mode!='unsigned': args=['-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',logtree]
  head=git(*args,data=stamp.encode())
  if mode!='absent': git('update-ref',v['LOG_REF'],head)
  if mode in ['chosen','input-chosen']:
   ref='refs/tags/evidence/'+tree+'/'+record if mode=='chosen' else 'refs/tags/evidence/input/check/'+ik+'/'+record
   git('update-ref',ref,record)
  input_key=ik if mode.startswith('input-') else None
  now=v['datetime'](1970,1,1,tzinfo=v['timezone'].utc)+v['timedelta'](microseconds=micros)
  expected=v['log_view'](str(repo),str(keys),tree,'check',input_key,chosen,now,max_age)
  rows.append(dict(repo=str(repo),keys=str(keys),tree=tree,key=input_key,chosen=chosen,now=micros,max_age=max_age,expected=expected))
  # Persist each signers list separately because later cases change it.
  saved=repo/'allowed'; saved.write_bytes(keys.read_bytes()); rows[-1]['keys']=str(saved)
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
    for row in rows {
        let actual = read(
            Path::new(row["repo"].as_str().unwrap()),
            Path::new(row["keys"].as_str().unwrap()),
            row["tree"].as_str().unwrap(),
            "check",
            row["key"].as_str(),
            row["chosen"].as_str(),
            row["now"].as_i64().unwrap(),
            row["max_age"].as_i64().unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            row["expected"],
            "{row}"
        );
    }
}

use super::*;
use crate::evidence::{legacy_output, legacy_policy::PolicyDocument};
use serde_json::{Value, json};
#[test]
fn single_log_overlay_matches_complete_signed_git_oracle() {
    let script = r#"
import json,pathlib,runpy,subprocess,sys
from datetime import datetime,timezone
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); rows=[]
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[2])/fmt; root.mkdir(); key=root/'key'
 subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 host=root/'host'; subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(host)],check=True)
 keys=root/'keys'; keys.write_text('agent/fixture '+key.with_suffix('.pub').read_text()+'host/fixture '+host.with_suffix('.pub').read_text())
 logs=root/'logkeys'; logs.write_text('log/fixture '+key.with_suffix('.pub').read_text())
 for mode in ['absent','unsigned','fresh','missing','failed','skip-fail','projection-failure','projection-exception','crate','empty-log','logged','crate-logged']:
  repo=root/mode; subprocess.run(['git','init','-q','--bare','--object-format='+fmt,str(repo)],check=True)
  def git(*a,data=None): return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
  git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
  def blob(data): return git('hash-object','-w','--stdin',data=data)
  def tree(data=b''): return git('mktree',data=data)
  current=tree(('100644 blob '+blob(b'invalid json')+'\tconfig.json\n').encode()); subject=git('commit-tree',current,data=b'subject')
  def record(label,time,exit,level='agent'):
   value=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=subject,digest=dict(gitTree=current))],predicate=dict(schema_version=1,tier='full',change_id=label,signer=level+'/fixture',observed_at='2026-01-01T00:0'+time+'Z',observed=dict(kind='tests',runner='wrapper',inputs={'crate':'c','source_inputs':'1'*len(current),'tests_run':'1'},checks={'check':dict(command=['true'],exit_code=exit,output_sha256='0'*64)})))
   note=tree(('100644 blob '+blob(json.dumps(value).encode())+'\t'+current+'\n').encode())
   commit=git('-c','gpg.format=ssh','-c','user.signingkey='+str(host if level=='host' else key),'commit-tree','-S',note,'-p',subject,data=label.encode()); git('update-ref','refs/tags/evidence/'+current+'/'+commit,commit); return commit
  chosen=record('old','3:00',1 if mode in ['failed','skip-fail'] else 0)
  if mode=='skip-fail': record('new','4:00',0,'host')
  entry=dict(trust_levels=['agent'],require='reject',kinds={'wrapper':dict(command=['true'])})
  if mode=='projection-failure': entry['inputs']=['config.json::x']
  policy=json.dumps(dict(version=1,checks={'check':entry})); rules=v['policy_rules'](policy,'check','fixture')
  if mode in ['projection-exception','crate','crate-logged']: rules['inputs']=['!\ud800']
  logtree=tree()
  if mode=='missing': logtree=tree(('100644 blob '+blob(('record '+subject+' check x y z\n').encode())+'\t'+current+'\n').encode()); logtree=tree(('040000 tree '+logtree+'\t'+current[:2]+'\n').encode()); logtree=tree(('040000 tree '+logtree+'\ttrees\n').encode())
  if mode=='logged': logtree=tree(('100644 blob '+blob(('record '+chosen+' check x y z\n').encode())+'\t'+current+'\n').encode()); logtree=tree(('040000 tree '+logtree+'\t'+current[:2]+'\n').encode()); logtree=tree(('040000 tree '+logtree+'\ttrees\n').encode())
  if mode=='crate-logged':
   ik='1'*len(current); logtree=tree(('100644 blob '+blob(('record '+chosen+' check x y z\n').encode())+'\t'+ik+'\n').encode())
   for name in [ik[:2],'check','keys']: logtree=tree(('040000 tree '+logtree+'\t'+name+'\n').encode())
  args=['commit-tree',logtree] if mode=='unsigned' else ['-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',logtree]
  head=git(*args,data=b'as_of=2026-01-01T00:05:00Z')
  if mode not in ['absent','empty-log']: git('update-ref',v['LOG_REF'],head)
  logkeys='' if mode=='empty-log' else str(logs); binding=('c','1'*len(current),True) if mode in ['crate','crate-logged'] else None
  try: expected=dict(value=v['verify'](str(repo),current,'check',str(keys),None,rules=rules,log_keys=logkeys,crate_key=binding,now=datetime(2026,1,1,0,5,tzinfo=timezone.utc)))
  except v['Failure'] as e: expected=dict(reason=e.reason,detail=list(map(ord,str(e))),extra=e.extra)
  except Exception as e: expected=dict(exception=type(e).__name__,detail=list(map(ord,str(e))))
  if mode in ['fresh','logged','crate-logged']: assert expected['value']['log']==('unlogged_pass' if mode=='fresh' else 'ok'),expected
  rows.append(dict(repo=str(repo),tree=current,keys=str(keys),logkeys=logkeys,policy=policy,crate=binding,expected=expected,mode=mode))
print(json.dumps(rows))
"#;
    let root = tempfile::tempdir().unwrap();
    let out = crate::pinned_python::command()
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
    assert_eq!(rows.len(), 24);
    for (row, transport) in rows
        .iter()
        .flat_map(|row| [Transport::Native, Transport::Cli].map(move |mode| (row, mode)))
    {
        let mut rules = PolicyDocument::parse(row["policy"].as_str().unwrap(), "check")
            .unwrap()
            .into_rules("fixture")
            .unwrap();
        if matches!(
            row["mode"].as_str(),
            Some("projection-exception" | "crate" | "crate-logged")
        ) {
            rules.header.inputs = Some(vec![
                crate::evidence::legacy_policy::normalized_text::NormalizedText::Codepoints(vec![
                    33, 0xd800,
                ]),
            ]);
        }
        let q = Request {
            repo: Path::new(row["repo"].as_str().unwrap()),
            tree: row["tree"].as_str().unwrap(),
            check: "check".into(),
            keys: Path::new(row["keys"].as_str().unwrap()),
            inputs: None,
            crate_key: row["crate"]
                .as_array()
                .map(|b| super::super::collection::CrateBinding {
                    name: "c".into(),
                    key: b[1].as_str().unwrap(),
                    needs_tests: true,
                }),
        };
        let mut judgment = CheckJudgment {
            clock: &mut 1_767_225_900_000_000i64,
            run_inputs: &BTreeMap::new(),
            lane: None,
            provider: LaneOnce::new(GitProvider {
                repo: q.repo,
                tree: q.tree,
            }),
        };
        let outcome = verify_with_transport(
            &q,
            Settings::Policy(&rules),
            &mut judgment,
            Levels::Utf8(&[]),
            Some(super::super::log_view::Request {
                keys: Path::new(row["logkeys"].as_str().unwrap()),
                now_micros: 1_767_225_900_000_000,
            }),
            transport,
        );
        let actual = match outcome {
            Ok((retained, log)) => {
                let mut text = String::new();
                retained
                    .with_view(q.tree, q.check, |view| {
                        legacy_output::write(&mut text, |w| {
                            view.write_extended_json(w, |o| {
                                if let Some(log) = log {
                                    log.write_fields(o)?;
                                }
                                Ok(())
                            })
                        })
                    })
                    .unwrap()
                    .unwrap();
                json!({"value":serde_json::from_str::<Value>(&text).unwrap()})
            }
            Err(e) => match e.failure.origin {
                crate::evidence::legacy_policy::ErrorOrigin::Exception { class } => {
                    json!({"exception":class,"detail":e.failure.detail.borrowed().points().collect::<Vec<_>>()})
                }
                crate::evidence::legacy_policy::ErrorOrigin::Failure => {
                    let mut extra = serde_json::Map::new();
                    if let Some(n) = e.failure.attempts {
                        extra.insert("attempts".into(), json!(n));
                    }
                    if let Some(c) = e.decided_by {
                        extra.insert("decided_by".into(), json!(c));
                    }
                    if let Some(c) = e.skipped_newer {
                        extra.insert("skipped_newer".into(), json!(c));
                    }
                    if let Some(log) = e.log {
                        extra.extend(
                            serde_json::to_value(log)
                                .unwrap()
                                .as_object()
                                .unwrap()
                                .clone(),
                        );
                    }
                    json!({"reason":e.failure.reason,"detail":e.failure.detail.borrowed().points().collect::<Vec<_>>(),"extra":extra})
                }
            },
        };
        assert_eq!(actual, row["expected"], "{}", row["mode"]);
    }
}

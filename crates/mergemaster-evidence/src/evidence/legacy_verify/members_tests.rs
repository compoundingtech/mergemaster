use super::*;
use serde_json::Value;

#[test]
fn sorted_loop_refusals_match_the_pinned_oracle() {
    // Isolate the oracle's aggregation loop from record selection (which has
    // signed-Git differential fixtures of its own); execute the original body.
    let script = r#"
import ast,json,pathlib,sys,concurrent.futures,threading
source=ast.parse((pathlib.Path(sys.argv[1])/'scripts/evidence-verify').read_text())
node=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='verify_members')
class Failure(Exception):
 def __init__(self,reason,detail='',**extra): self.reason=reason; self.detail=detail; self.extra=extra
out=[]
for count in [1,2,12,13,20]:
 for mode in ['no_key','ordinary','exception']:
  names=[f'crate-{i:02}' for i in reversed(range(count))]
  members={n:None if mode=='no_key' else '1'*40 for n in names}
  def verified(*a):
   if mode=='exception': raise ValueError('conversion')
   raise Failure('no_record','not included in the aggregate')
  env=dict(concurrent=concurrent,threading=threading,Failure=Failure,member_keys=lambda *a:members,zero_test_crates=lambda *a:set(),verified=verified)
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<oracle>','exec'),env)
  try: env['verify_members']('repo','tree','check','keys',None,None,None,None,None,None,None,None,None,None,'base')
  except Failure as e: result=dict(reason=e.reason,detail=e.detail,**e.extra)
  except ValueError as e: result=dict(exception=str(e))
  out.append(dict(names=names,mode=mode,result=result))
print(json.dumps(out))
"#;
    let output = crate::pinned_python::command()
        .args([
            "-c",
            script,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases {
        let mode = case["mode"].as_str().unwrap();
        let mut members: Vec<_> = case["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                (
                    n.as_str().unwrap().to_owned(),
                    (mode != "no_key").then(|| "1".repeat(40)),
                    true,
                )
            })
            .collect();
        members.sort_by(|a, b| a.0.cmp(&b.0));
        let mut called = Vec::new();
        let result = collect::<()>(members, |name, _, needs_tests| {
            called.push(name.to_owned());
            assert!(needs_tests);
            Err(if mode == "exception" {
                Failure::exception("ValueError", "conversion")
            } else {
                Failure {
                    reason: "no_record",
                    detail: "not included in the aggregate".into(),
                    attempts: Some(9),
                    origin: ErrorOrigin::Failure,
                }
            })
        });
        match result {
            Err(Refusal::Uncovered(error)) => {
                assert_eq!(error.failure.reason, case["result"]["reason"]);
                assert_eq!(
                    error.failure.detail.borrowed().points().collect::<Vec<_>>(),
                    case["result"]["detail"]
                        .as_str()
                        .unwrap()
                        .chars()
                        .map(u32::from)
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    serde_json::to_value(&error.missing).unwrap(),
                    case["result"]["missing"]
                );
                assert_eq!(
                    error.members,
                    case["result"]["members"].as_u64().unwrap() as usize
                );
                assert_eq!(error.failure.attempts, None);
            }
            Err(Refusal::Verification(error)) => {
                assert_eq!(
                    error.origin,
                    ErrorOrigin::Exception {
                        class: "ValueError"
                    }
                );
                assert_eq!(called, ["crate-00"]);
            }
            Ok(_) => panic!("expected refusal"),
        }
        if mode == "no_key" {
            assert!(called.is_empty());
        }
        if mode == "ordinary" {
            assert!(called.windows(2).all(|w| w[0] < w[1]));
        }
    }
    let pass = collect(
        vec![("a".into(), Some("key".into()), false)],
        |_, _, tests| Ok(tests),
    )
    .unwrap();
    assert_eq!(pass.iter().collect::<Vec<_>>(), [("a", "key", &false)]);
}

#[test]
fn retained_cross_tree_members_share_one_check_budget() {
    use super::super::{candidates::LaneOnce, configured::GitProvider};
    use crate::evidence::legacy_policy::PolicyDocument;
    use std::path::Path;

    let script = r#"
import json,pathlib,runpy,subprocess,sys
root=pathlib.Path(sys.argv[2]); v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
key=root/'key'
subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
keys=root/'keys'; keys.write_text('agent/fixture '+key.with_suffix('.pub').read_text())
cases=[]
for fmt in ['sha1','sha256']:
 repo=root/fmt
 subprocess.run(['git','init','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
 def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
 def write(name,data):
  p=repo/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(data)
 git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
 names=['a','b','c','d']
 write('Cargo.toml','[workspace]\nmembers='+json.dumps(names))
 for name in names:
  write(name+'/Cargo.toml','[package]\nname="'+name+'"')
  write(name+'/src/lib.rs','pub fn '+name+'() {}')
 write('.st/rust-test-inputs.json',json.dumps({'global':[],
  'crates':{name:{'extra':[name+'/src/lib.rs']} for name in names}}))
 git('add','.'); current=git('write-tree').decode().strip()
 projected=json.loads(subprocess.check_output([sys.executable,sys.argv[3],'--repo',str(repo),'--tree',current,
  '--inputs-from',current,'--verifier',sys.argv[1]+'/scripts/evidence-verify','--json']))
 assert len(set(projected.values()))==len(names),projected
 def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
 def tree(data=b''): return git('mktree',data=data).decode().strip()
 records={}
 for name in names:
  target=tree(('100644 blob '+blob(name.encode())+'\tother\n').encode())
  subject=git('commit-tree',target,data=b'subject').decode().strip()
  value=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],
   subject=[dict(name=subject,digest=dict(gitTree=target))],
   predicate=dict(schema_version=1,tier='full',change_id=name,signer='agent/fixture',observed_at='2026-01-01T00:04:00Z',
    observed=dict(kind='tests',runner='wrapper',inputs={'crate':name,'source_inputs':projected[name],'tests_run':'1'},
     checks={'check':dict(command=['true'],exit_code=0,output_sha256='0'*64)})),extra=[0]*500000)
  data=json.dumps(value,separators=(',',':')).encode(); assert len(data)<=1048576
  note=tree(('100644 blob '+blob(data)+'\t'+target+'\n').encode())
  record=git('-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',note,'-p',subject,data=name.encode()).decode().strip()
  git('update-ref','refs/tags/evidence/input/check/'+projected[name]+'/'+record,record)
  records[name]=record
 cases.append(dict(repo=str(repo),tree=current,keys=str(keys),records=records))
print(json.dumps(cases))
"#;
    let root = tempfile::tempdir().unwrap();
    let mut command = crate::pinned_python::command();
    crate::gate::git::sanitize(&mut command);
    let output = command
        .env("HOME", root.path())
        .env("GNUPGHOME", root.path())
        .env("XDG_CONFIG_HOME", root.path())
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .arg(root.path())
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/fractal/scripts/rust-test-keys"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 2);
    let rules = PolicyDocument::parse(
        r#"{"version":1,"checks":{"check":{"trust_levels":["agent"],"require":"reject","kinds":{"wrapper":{"command":["true"]}}}}}"#,
        "check",
    )
    .unwrap()
    .into_rules("fixture")
    .unwrap();
    for (case, transport) in cases.iter().flat_map(|case| {
        [configured::Transport::Native, configured::Transport::Cli]
            .map(move |transport| (case, transport))
    }) {
        let q = Request {
            repo: Path::new(case["repo"].as_str().unwrap()),
            tree: case["tree"].as_str().unwrap(),
            check: "check".into(),
            keys: Path::new(case["keys"].as_str().unwrap()),
            inputs: None,
            crate_key: None,
        };
        let mut clock = 1_767_225_900_000_000i64;
        let mut judgment = CheckJudgment {
            clock: &mut clock,
            run_inputs: &BTreeMap::new(),
            lane: None,
            provider: LaneOnce::new(GitProvider {
                repo: q.repo,
                tree: q.tree,
            }),
        };
        let members = Members::read(q.repo, q.tree, Some(q.tree.into())).unwrap();
        let mut retained = Vec::new();
        // Each member independently fits, with a distinct original document
        // reachable only through its cross-tree source-input index.
        for (name, binding) in members.iter() {
            let note = configured::retained_with_transport(
                &Request {
                    crate_key: binding,
                    ..q
                },
                Settings::Policy(&rules),
                &mut judgment,
                Levels::Utf8(&[]),
                transport,
            )
            .unwrap();
            assert_eq!(note.record().candidate.commit, case["records"][name]);
            retained.push(note);
        }
        assert_eq!(retained.len(), 4);
        let error = verified_with_transport(
            &q,
            Some(q.tree.into()),
            Settings::Policy(&rules),
            &mut judgment,
            Levels::Utf8(&[]),
            None,
            transport,
        )
        .err()
        .expect("several retained members must exceed the shared record budget");
        let Refusal::Verification(error) = error else {
            panic!("budget exhaustion must abort, not become crate_uncovered");
        };
        assert_eq!(error.origin, ErrorOrigin::Failure);
        assert_eq!(error.reason, "record-budget-exceeded");
        assert_eq!(
            error.detail.to_string(),
            "check record ownership or cache entry limit exceeded"
        );
        assert_eq!(error.attempts, None);
    }
}

use super::*;
use crate::evidence::{
    legacy_policy::{PolicyDocument, PolicyError},
    legacy_verify::{
        candidates::LaneOnce,
        judgment::{LaneDefinition, Provider},
    },
};
use serde_json::{Value, json};

#[test]
fn signed_member_log_overlays_match_the_complete_oracle() {
    let script = r#"
import json,pathlib,runpy,subprocess,sys,types
from datetime import datetime,timezone
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
rtk=types.SimpleNamespace(**runpy.run_path(sys.argv[3])); v['member_keys'].__globals__['sibling']=lambda name:rtk
class Clock(datetime):
 @classmethod
 def now(cls,tz=None): return datetime(2026,1,1,0,5,tzinfo=timezone.utc)
v['members_log_view'].__globals__['datetime']=Clock
cases=[]
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[2])/fmt; root.mkdir(); keys=root/'keys'; lines=[]
 for level in ['host','agent','other']:
  key=root/level; subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
  lines.append(level+'/fixture '+key.with_suffix('.pub').read_text())
 keys.write_text(''.join(lines))
 log_keys=root/'log-keys'; log_keys.write_text('log/fixture '+(root/'host.pub').read_text())
 for mode in ['plain','tie','cross','events','empty-events','attempts','allowance','zero','exception','missing','lane','other','duplicates','log-absent','log-covered','log-unlogged','log-missing','log-failure','log-exception','empty-log','log-surrogate','log-mixed-surrogate']:
  repo=root/('repo-'+mode); repo.mkdir()
  def git(*a,data=None): return subprocess.check_output(['git','-C',str(repo),*a],input=data,stderr=subprocess.PIPE).decode().strip()
  git('init','--object-format='+fmt); git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
  def write(p,s):
   p=repo/p; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(s)
  write('Cargo.toml','[workspace]\nmembers=["z","b","a"]')
  for name in ['z','b','a']: write(name+'/Cargo.toml','[package]\nname="'+name+'"')
  inputs=dict(global_=[],crates={n:dict(extra=[]) for n in ['a','b','z']})
  inputs['global']=inputs.pop('global_'); inputs['no_tests']=['b'] if mode=='allowance' else []
  write('.st/rust-test-inputs.json',json.dumps(inputs)); git('add','.'); base=git('write-tree')
  write('unrelated','different tree'); git('add','.'); tree=git('write-tree')
  members=v['member_keys'](str(repo),tree,base); assert len(members)==3
  command=['true','line\n😀']; levels={'a':'host','b':'other','z':'agent'}
  if mode=='other': levels={n:'other' for n in levels}
  kind=dict(command=command)
  if mode in ['events','empty-events','lane','duplicates']:
   kind['by_level']={l:dict(command=command,events=(['pull_request'] if mode=='empty-events' and l=='host' else ['merge_group'] if mode=='empty-events' else ['pull_request','merge_group'])) for l in ['host','agent','other']}
   if mode=='lane':
    for entry in kind['by_level'].values(): entry['lane']=True
  entry=dict(trust_levels=['host','agent','other'],kinds=dict(wrapper=kind))
  if mode in ['events','empty-events','duplicates']: entry['events']=['merge_group','pull_request']
  policy=None if mode=='plain' else json.dumps(dict(version=1,checks=dict(check=entry)))
  rules=None if policy is None else v['policy_rules'](policy,'check','fixture')
  if mode=='duplicates':
   rules['events']=['pull_request','merge_group','pull_request']
   rules['kinds']['wrapper']['by_level']['agent']['events']=['merge_group','pull_request','merge_group']
  written={}
  def record(name,minute,serial=0):
   if mode in ['missing','log-failure'] and name=='a': return
   target=base if mode=='cross' and name=='a' else tree
   parent=git('commit-tree',target,data=b'subject')
   ran='0' if name=='b' and mode in ['allowance','zero'] else '²' if name=='b' and mode in ['exception','log-exception'] else '1'
   inp=dict(crate=name,source_inputs=members[name],tests_run=ran,echo='\ud800\n😀')
   sep='\ud800' if mode=='log-surrogate' or (mode=='log-mixed-surrogate' and name=='b') else 'T'
   statement=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=parent,digest=dict(gitTree=target))],predicate=dict(schema_version=1,tier='full',change_id=name,signer=levels[name]+'/fixture',observed_at=f'2026-01-01{sep}00:0{minute}:00Z',observed=dict(kind='tests',runner='wrapper',inputs=inp,checks=dict(check=dict(command=command,exit_code=0,output_sha256='0'*64)))))
   blob=git('hash-object','-w','--stdin',data=json.dumps(statement).encode()); note=git('mktree',data=f'100644 blob {blob}\t{target}\n'.encode())
   commit=git('-c','gpg.format=ssh','-c','user.signingkey='+str(root/levels[name]),'commit-tree','-S',note,'-p',parent,data=f'{name}-{serial}'.encode())
   if serial==0: written[name]=commit
   git('update-ref',f'refs/tags/evidence/{target}/{commit}',commit)
   if target!=tree: git('update-ref',f'refs/tags/evidence/input/check/{members[name]}/{commit}',commit)
  for name,minute in [('z',3),('b',1),('a',4)]: record(name,2 if mode=='tie' else minute)
  if mode=='attempts': record('z',0,1); record('z',1,2)
  if mode.startswith('log-') and mode!='log-absent':
   listed=list(written.values()) if mode=='log-covered' else []
   if mode in ['log-missing','log-failure']:
    listed.append(git('commit-tree',tree,data=b'not locally indexed'))
   path='keys/check/'+members['z'][:2]+'/'+members['z'] if mode=='log-failure' else 'trees/'+tree[:2]+'/'+tree
   write(path,''.join('record '+c+' check x y z\n' for c in listed))
   git('add','.'); logtree=git('write-tree')
   loghead=git('-c','gpg.format=ssh','-c','user.signingkey='+str(root/'host'),'commit-tree','-S',logtree,data=b'as_of=2026-01-01T00:05:00Z')
   git('update-ref',v['LOG_REF'],loghead)
  shadow=str(log_keys)+('\0' if mode=='log-exception' else '') if mode.startswith('log-') else '' if mode=='empty-log' else None
  calls=[]
  def lane(): calls.append(1); return None
  try:
   result=v['verify_members'](str(repo),tree,'check',str(keys),None,v['KINDS'],[],None,None,None,rules,None,lane if mode=='lane' else None,{},base,shadow)
   expected=dict(wire=json.dumps(result,indent=2))
  except v['Failure'] as e: expected=dict(reason=e.reason,detail=e.detail,**e.extra)
  except Exception as e: expected=dict(exception=type(e).__name__,detail=str(e))
  assert ('wire' in expected)==(mode not in ['zero','exception','missing','lane','log-failure','log-exception']),(mode,expected)
  if 'wire' in expected:
   assert list(result['crates'])==['a','b','z']
   if mode=='tie': assert result['record']==written['a']
   if mode=='other': assert result['trust_level']=='other'
   if mode=='cross': assert result['match']=='inputs'
   if mode=='attempts': assert result['attempts']==3
   if mode=='duplicates': assert result['events']==['merge_group','pull_request','merge_group']
   if mode=='empty-events': assert result['events']==[]
  wire=result if 'wire' in expected else dict(satisfied=False,reason=expected.get('reason','error'),check='check',detail=(expected['exception']+': '+expected['detail'] if 'exception' in expected else expected['detail']),**{k:value for k,value in expected.items() if k not in ['reason','detail','exception']})
  wire=json.dumps(wire,indent=2)
  cases.append(dict(repo=str(repo),tree=tree,base=base,keys=str(keys),log_keys=shadow,policy=policy,mode=mode,expected=expected,wire=wire,calls=len(calls)))
print(json.dumps(cases))
"#;
    let root = tempfile::tempdir().unwrap();
    let mut command = crate::pinned_python::command();
    crate::gate::git::sanitize(&mut command);
    let output = command
        .env("HOME", root.path())
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap())
        .arg(root.path())
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
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
    struct LaneCounter<'a>(&'a std::cell::Cell<usize>);
    impl Provider for LaneCounter<'_> {
        fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
            self.0.set(self.0.get() + 1);
            Ok(None)
        }
        fn blob_sha256(
            &mut self,
            _: super::super::judgment::BindingPath<'_>,
        ) -> Result<Option<String>, PolicyError> {
            panic!("no file bindings")
        }
    }
    for (case, transport) in cases.iter().flat_map(|case| {
        [configured::Transport::Native, configured::Transport::Cli].map(move |mode| (case, mode))
    }) {
        let mut rules = case["policy"].as_str().map(|p| {
            PolicyDocument::parse(p, "check")
                .unwrap()
                .into_rules("fixture")
                .unwrap()
        });
        if case["mode"] == "duplicates" {
            let rules = rules.as_mut().unwrap();
            rules.header.events = Some(vec![
                "pull_request".into(),
                "merge_group".into(),
                "pull_request".into(),
            ]);
            for (_, kind) in &mut rules.kinds {
                for (name, level) in &mut kind.by_level {
                    if name.borrowed().equals("agent") {
                        level.events = vec![
                            "merge_group".into(),
                            "pull_request".into(),
                            "merge_group".into(),
                        ];
                    }
                }
            }
        }
        let kinds = vec!["wrapper".chars().map(u32::from).collect()];
        let options = super::super::judgment::Unconfigured {
            routing: super::super::routing::Unconfigured {
                kinds: &kinds,
                trust_levels: None,
                runner_prefix: None,
            },
            command: None,
            max_age: None,
            bindings: &[],
        };
        let settings = rules
            .as_ref()
            .map_or(Settings::Unconfigured(&options), Settings::Policy);
        let mut clock = 1_767_225_900_000_000i64;
        let run = BTreeMap::new();
        let calls = std::cell::Cell::new(0);
        let mut judgment = CheckJudgment {
            clock: &mut clock,
            run_inputs: &run,
            lane: None,
            provider: LaneOnce::new(LaneCounter(&calls)),
        };
        let q = Request {
            repo: std::path::Path::new(case["repo"].as_str().unwrap()),
            tree: case["tree"].as_str().unwrap(),
            check: "check".into(),
            keys: std::path::Path::new(case["keys"].as_str().unwrap()),
            inputs: None,
            crate_key: None,
        };
        let outcome = verified_with_transport(
            &q,
            case["base"].as_str().map(Into::into),
            settings,
            &mut judgment,
            Levels::Unrestricted,
            case["log_keys"]
                .as_str()
                .map(|keys| super::super::log_view::Request {
                    keys: std::path::Path::new(keys),
                    now_micros: Some(1_767_225_900_000_000),
                }),
            transport,
        );
        let wrapped = super::super::cli_verified::Outcome::Members(outcome);
        let mut wire = String::new();
        wrapped.write(q.tree, q.check, &mut wire).unwrap().unwrap();
        assert_eq!(wire, case["wire"].as_str().unwrap());
        let super::super::cli_verified::Outcome::Members(outcome) = wrapped else {
            unreachable!()
        };
        let actual = match outcome {
            Ok(aggregate) => {
                let wire = aggregate
                    .with_view(q.tree, q.check, |view| {
                        let mut wire = String::new();
                        crate::evidence::legacy_output::write(&mut wire, |w| view.write_json(w))
                            .unwrap();
                        wire
                    })
                    .unwrap();
                json!({"wire":wire})
            }
            Err(Refusal::Uncovered(e)) => {
                assert_eq!(e.keys.len(), e.members);
                let mut value = json!({"reason":e.failure.reason,"detail":e.failure.detail.to_string(),"missing":e.missing,"members":e.members});
                if let Some(log) = e.log {
                    value.as_object_mut().unwrap().extend(
                        serde_json::to_value(log)
                            .unwrap()
                            .as_object()
                            .unwrap()
                            .clone(),
                    );
                }
                value
            }
            Err(Refusal::Verification(e)) => match e.origin {
                ErrorOrigin::Exception { class } => {
                    json!({"exception":class,"detail":e.detail.to_string()})
                }
                ErrorOrigin::Failure => json!({"reason":e.reason,"detail":e.detail.to_string()}),
            },
        };
        assert_eq!(actual, case["expected"], "{}", case["mode"]);
        assert_eq!(calls.get(), case["calls"].as_u64().unwrap() as usize);
    }
    assert_eq!(cases.len(), 44);
}

use super::*;
use serde_json::{Value, json};

#[test]
fn require_all_matches_sorted_joined_git_oracle() {
    let script = r#"
import json,pathlib,runpy,subprocess,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
for fmt in ['sha1','sha256']:
 root=pathlib.Path(sys.argv[2])/fmt; root.mkdir(); key=root/'key'
 subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
 keys=root/'keys'; keys.write_text('agent/fixture '+key.with_suffix('.pub').read_text())
 for name in ['empty','off','off-bypass','invalid-off','satisfied','shadow','reject','mixed','no-lane','eager-good','eager-after','policy-after','verify-error','budget','clock-exception','age-overflow']:
  repo=root/name; subprocess.run(['git','init','--bare','--object-format='+fmt,str(repo)],check=True,stdout=subprocess.DEVNULL)
  def git(*args,data=None): return subprocess.check_output(['git','-C',str(repo),*args],input=data)
  git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
  def blob(data): return git('hash-object','-w','--stdin',data=data).decode().strip()
  def tree(files={}): return git('mktree',data=b''.join(('100644 blob '+blob(data)+'\t'+path+'\n').encode() for path,data in sorted(files.items()))).decode().strip()
  current=tree({'input':b'content','def':b'definition'}); base=git('commit-tree',current,data=b'subject').decode().strip()
  def entry(mode='reject'): return dict(require=mode,trust_levels=['agent'],kinds={'wrapper':dict(command=['true'])})
  checks={point:entry() for point in ['😀','z','\ud800','a']}; lane=None
  if name=='empty': checks={}
  if name in ['off','off-bypass','invalid-off']: checks={'a':entry('off')}
  if name=='invalid-off': checks['a']['unexpected']=True
  if name in ['shadow','reject']: checks={'b':entry(name)}
  if name=='mixed': checks={'z':entry(),'c':entry(),'b':entry('shadow'),'a':entry()}
  if name in ['eager-after','policy-after','budget','clock-exception','age-overflow']: checks={'z':entry(),'b':entry(),'a':entry()}
  if name=='policy-after': checks['b']['unexpected']=True
  if name=='budget': checks['b']['inputs']=['input']
  if name=='age-overflow': checks['b']['max_age_s']=86400000000000
  if name in ['no-lane','eager-good','eager-after']:
   lanes={} if name=='no-lane' else {point:dict(argv=['true'],definition_paths=['def']) for point in checks}
   if name=='eager-after': lanes['b']['argv']=[]
   lane=json.dumps(dict(version=1,lanes=lanes))
  inputs={}
  if name in ['eager-good','eager-after']: inputs['lane_definition_sha256']=v['lane_for'](str(repo),current,(lane,base),'a')['sha256']
  def record(label,target,points,extra_inputs,wide=False):
   parent=base if target==current else git('commit-tree',target,data=b'other subject').decode().strip()
   value=dict(_type=v['STATEMENT_TYPE'],predicateType=v['PREDICATE_TYPE'],subject=[dict(name=parent,digest=dict(gitTree=target))],predicate=dict(
    schema_version=1,tier='full',change_id=label,signer='agent/fixture',observed_at='2026-01-01T00:00:00Z',observed=dict(kind='tests',runner='wrapper',inputs=extra_inputs,
    checks={point:dict(command=['true'],exit_code=0,output_sha256='0'*64) for point in points})))
   if wide: value['extra']=[0]*500000
   data=json.dumps(value,separators=(',',':')).encode(); assert len(data)<=1048576
   note=tree({target:data}); commit=git('-c','gpg.format=ssh','-c','user.signingkey='+str(key),'commit-tree','-S',note,'-p',parent,data=label.encode()).decode().strip()
   ref='refs/tags/evidence/'+target if target==current else 'refs/tags/evidence/input/b/'+extra_inputs['source_inputs']
   git('update-ref',ref+'/'+commit,commit)
  record('good',current,['a','z','\ud800','😀']+(['b'] if name in ['clock-exception','age-overflow'] else []),inputs)
  if name=='budget':
   other=tree(); projection=v['project'](str(repo),current,['input'])
   for i in range(3): record('wide'+str(i),other,['b'],{'source_inputs':projection},True)
  target='not-a-tree' if name=='off-bypass' else current
  use_repo=str(root/'absent') if name in ['off-bypass','verify-error'] else str(repo)
  if name=='off-bypass': lane='malformed lane file never reached'
  policy=json.dumps(dict(version=1,checks=checks))
  namespace=v['verified'].__globals__; original=namespace['datetime']
  class Sample(original):
   calls=0
   @classmethod
   def now(cls,tz):
    cls.calls+=1
    if cls.calls==2: raise OverflowError('clock refused')
    return original(2026,1,1,0,1,tzinfo=tz)
  if name=='clock-exception': namespace['datetime']=Sample
  def verify(text):
   try:
    result=v['require_all'](use_repo,target,str(keys),text,'fixture',None if lane is None else (lane,base))
    result['lanes']=[[list(map(ord,point)),dict(item,tier=list(map(ord,item['tier']))) if item['satisfied'] else {k:item[k] for k in ['require','satisfied','reason','decision']}] for point,item in result['lanes'].items()]
    return result
   except v['Failure'] as e: return dict(global_reason=e.reason)
   except OverflowError: return dict(global_reason='error')
  control=json.dumps(dict(version=1,checks={'a':entry()})) if name in ['eager-after','policy-after','budget','clock-exception','age-overflow'] else None
  if control: assert verify(control)['satisfied'],name
  Sample.calls=0
  expected=verify(policy)
  if name=='clock-exception': assert Sample.calls==2,name
  namespace['datetime']=original
  if name in ['invalid-off','eager-after','policy-after','clock-exception','age-overflow']: assert expected.get('global_reason')=='error',(name,expected)
  elif name in ['empty','off','off-bypass','satisfied','eager-good','budget']: assert expected['satisfied'],(name,expected)
  else:
   reason={'no-lane':'no_lane','verify-error':'error'}.get(name,'wrong_check')
   assert any(item.get('reason')==reason for _,item in expected['lanes']),(name,expected)
  if name=='budget':
   expected['satisfied']=False; expected['decision']='reject'
   expected['lanes'][1][1]=dict(require='reject',satisfied=False,reason='record-budget-exceeded',decision='reject')
  cases.append(dict(name=fmt+'/'+name,repo=use_repo,tree=target,keys=str(keys),policy=policy,lane=lane,base=base,control=control,expected=expected))
print(json.dumps(cases))
"#;
    let root = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new("python3");
    crate::gate::git::sanitize(&mut command);
    let output = command
        .env("HOME", root.path())
        .env("GNUPGHOME", root.path())
        .env("XDG_CONFIG_HOME", root.path())
        .args([
            "-c",
            script,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
        ])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 32);
    struct Sampling(usize);
    impl CurrentTime for Sampling {
        fn epoch_micros(&mut self) -> Result<i64, PolicyError> {
            self.0 += 1;
            if self.0 == 2 {
                return Err(PolicyError {
                    reason: "error",
                    detail: "clock refused".into(),
                });
            }
            Ok(1_767_225_660_000_000)
        }
    }
    for case in cases {
        let run = |policy| {
            let mut sampling = Sampling(0);
            let mut system = SystemClock;
            let injected = case["name"].as_str().unwrap().ends_with("/clock-exception");
            let clock: &mut dyn CurrentTime = if injected { &mut sampling } else { &mut system };
            let result = with_clock(
                Path::new(case["repo"].as_str().unwrap()),
                case["tree"].as_str().unwrap(),
                case["keys"].as_str().unwrap(),
                policy,
                "fixture",
                case["lane"]
                    .as_str()
                    .map(|text| (text, case["base"].as_str().unwrap())),
                None,
                clock,
            );
            if injected {
                assert_eq!(
                    sampling.0,
                    if policy == case["policy"].as_str().unwrap() {
                        2
                    } else {
                        1
                    }
                );
            }
            result
        };
        if let Some(control) = case["control"].as_str() {
            assert!(run(control).unwrap().satisfied, "{}", case["name"]);
        }
        let actual = match run(case["policy"].as_str().unwrap()) {
            Err(error) => json!({"global_reason":error.reason}),
            Ok(all) => {
                let lanes: Vec<_> = all
                    .lanes
                    .into_iter()
                    .map(|(check, lane)| {
                        let value = match lane.outcome {
                            Ok(record) => json!({"require":lane.require,"satisfied":true,"decision":lane.decision,"record":record.record,"signer":record.signer,"tier":record.tier}),
                            Err(error) => json!({"require":lane.require,"satisfied":false,"decision":lane.decision,"reason":error.reason}),
                        };
                        json!([check,value])
                    })
                    .collect();
                json!({"mode":"require-all","tree":all.tree,"satisfied":all.satisfied,"decision":all.decision,"lanes":lanes})
            }
        };
        assert_eq!(actual, case["expected"], "{}", case["name"]);
    }
}
